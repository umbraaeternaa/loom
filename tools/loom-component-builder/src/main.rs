use std::{borrow::Cow, env, fs, process};

use wasm_encoder::{
    CanonicalOption, ComponentBuilder, ComponentExportKind, ComponentTypeRef,
    ComponentValType, CustomSection, ExportKind, ModuleArg, PrimitiveValType,
};
use wasmparser::{Parser, Payload, Validator, WasmFeatures};

const ENV_EXPORTS: [(&str, ExportKind); 8] = [
    ("push_handler", ExportKind::Func),
    ("pop_handler", ExportKind::Func),
    ("current_handler", ExportKind::Func),
    ("host_print", ExportKind::Func),
    ("push_caps", ExportKind::Func),
    ("pop_caps", ExportKind::Func),
    ("has_cap", ExportKind::Func),
    ("host_ffi", ExportKind::Func),
];

const BRIDGE_EXPORTS: [&str; 5] = [
    "loom_component_alloc_bytes",
    "loom_component_make_string",
    "loom_component_cons",
    "loom_component_record",
    "loom_component_variant",
];

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("loom-component-builder: {}", message.as_ref());
    process::exit(2)
}

fn read(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| fail(format!("cannot read {path}: {e}")))
}

fn validate_core(label: &str, bytes: &[u8]) {
    let mut validator = Validator::new_with_features(WasmFeatures::all());
    validator
        .validate_all(bytes)
        .unwrap_or_else(|e| fail(format!("invalid {label} core module: {e}")));
    let mut saw_module = false;
    for item in Parser::new(0).parse_all(bytes) {
        match item.unwrap_or_else(|e| fail(format!("cannot parse {label}: {e}"))) {
            Payload::Version { encoding, .. } => {
                if encoding != wasmparser::Encoding::Module {
                    fail(format!("{label} is not a core module"));
                }
                saw_module = true;
            }
            _ => {}
        }
    }
    if !saw_module {
        fail(format!("{label} has no core module header"));
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 7 {
        fail("usage: builder DENY.wasm LOOM.wasm ADAPTER.wasm EVIDENCE.json OUTPUT.wasm LOOM=WIT ...");
    }
    let deny = read(&args[1]);
    let loom = read(&args[2]);
    let adapter = read(&args[3]);
    let evidence = read(&args[4]);
    let output = &args[5];
    let exports: Vec<(&str, &str)> = args[6..]
        .iter()
        .map(|item| item.split_once('=').unwrap_or_else(|| fail("export mapping must be LOOM=WIT")))
        .collect();
    if exports.is_empty() {
        fail("at least one export mapping is required");
    }
    validate_core("deny-env", &deny);
    validate_core("loom-core", &loom);
    validate_core("loom-adapter", &adapter);

    let mut b = ComponentBuilder::default();
    let deny_module = b.core_module_raw(Some("deny-env"), &deny);
    let deny_instance = b.core_instantiate(Some("deny-env"), deny_module, []);
    let mut env_aliases = Vec::new();
    for (name, kind) in ENV_EXPORTS {
        let alias = b.core_alias_export(Some(name), deny_instance, name, kind);
        env_aliases.push((name, kind, alias));
    }
    let env_instance = b.core_instantiate_exports(Some("env"), env_aliases);

    let loom_module = b.core_module_raw(Some("loom-core"), &loom);
    let loom_instance = b.core_instantiate(
        Some("loom-core"),
        loom_module,
        [("env", ModuleArg::Instance(env_instance))],
    );
    let memory = b.core_alias_export(Some("loom-memory"), loom_instance, "memory", ExportKind::Memory);
    let mut loom_aliases = vec![("memory", ExportKind::Memory, memory)];
    for name in BRIDGE_EXPORTS {
        let alias = b.core_alias_export(Some(name), loom_instance, name, ExportKind::Func);
        loom_aliases.push((name, ExportKind::Func, alias));
    }
    for (loom_name, _) in &exports {
        let alias = b.core_alias_export(Some(loom_name), loom_instance, loom_name, ExportKind::Func);
        loom_aliases.push((loom_name, ExportKind::Func, alias));
    }
    let loom_namespace = b.core_instantiate_exports(Some("loom"), loom_aliases);

    let adapter_module = b.core_module_raw(Some("loom-adapter"), &adapter);
    let adapter_instance = b.core_instantiate(
        Some("loom-adapter"),
        adapter_module,
        [("loom", ModuleArg::Instance(loom_namespace))],
    );
    let cabi_memory = b.core_alias_export(
        Some("canonical-memory"), adapter_instance, "cm32p2_memory", ExportKind::Memory,
    );
    let realloc = b.core_alias_export(
        Some("canonical-realloc"), adapter_instance, "cm32p2_realloc", ExportKind::Func,
    );

    let (bytes_ty, bytes_enc) = b.type_defined(Some("bytes"));
    bytes_enc.list(PrimitiveValType::U8);
    let (result_ty, result_enc) = b.type_defined(Some("bytes-result"));
    result_enc.result(
        Some(ComponentValType::Type(bytes_ty)),
        Some(ComponentValType::Type(bytes_ty)),
    );
    let (func_ty, mut func_enc) = b.type_function(Some("invoke-type"));
    func_enc
        .params([("request", ComponentValType::Type(bytes_ty))])
        .result(Some(ComponentValType::Type(result_ty)));

    for (_, wit_name) in &exports {
        let internal = format!("cm32p2||{wit_name}");
        let post_name = format!("{internal}_post");
        let invoke = b.core_alias_export(Some(wit_name), adapter_instance, &internal, ExportKind::Func);
        let post = b.core_alias_export(Some(&post_name), adapter_instance, &post_name, ExportKind::Func);
        let lifted = b.lift_func(
            Some(wit_name),
            invoke,
            func_ty,
            [
                CanonicalOption::UTF8,
                CanonicalOption::Memory(cabi_memory),
                CanonicalOption::Realloc(realloc),
                CanonicalOption::PostReturn(post),
            ],
        );
        b.export(
            *wit_name,
            ComponentExportKind::Func,
            lifted,
            Some(ComponentTypeRef::Func(func_ty)),
        );
    }
    b.custom_section(&CustomSection {
        name: Cow::Borrowed("loom.component-adapter.v0"),
        data: Cow::Borrowed(&evidence),
    });
    let component = b.finish();
    Validator::new_with_features(WasmFeatures::all())
        .validate_all(&component)
        .unwrap_or_else(|e| fail(format!("invalid final component: {e}")));
    fs::write(output, component).unwrap_or_else(|e| fail(format!("cannot write {output}: {e}")));
}
