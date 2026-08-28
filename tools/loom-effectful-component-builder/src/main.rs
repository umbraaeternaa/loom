use std::{borrow::Cow, env, fs, process};

use wasm_encoder::{
    Alias, CanonicalOption, ComponentBuilder, ComponentExportKind, ComponentOuterAliasKind,
    ComponentTypeRef, ComponentValType, CustomSection, ExportKind, InstanceType, ModuleArg,
    PrimitiveValType, TypeBounds,
};
use wasmparser::{Parser, Payload, Validator, WasmFeatures};

const ENV_EXPORTS: [(&str, ExportKind); 9] = [
    ("push_handler", ExportKind::Func),
    ("pop_handler", ExportKind::Func),
    ("current_handler", ExportKind::Func),
    ("host_print", ExportKind::Func),
    ("push_caps", ExportKind::Func),
    ("pop_caps", ExportKind::Func),
    ("has_cap", ExportKind::Func),
    ("host_ffi", ExportKind::Func),
    ("host_rand", ExportKind::Func),
];

const BRIDGE_EXPORTS: [&str; 5] = [
    "loom_component_alloc_bytes",
    "loom_component_make_string",
    "loom_component_cons",
    "loom_component_record",
    "loom_component_variant",
];

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("loom-effectful-component-builder: {}", message.as_ref());
    process::exit(2)
}

fn read(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| fail(format!("cannot read {path}: {e}")))
}

fn validate_core(label: &str, bytes: &[u8]) {
    Validator::new_with_features(WasmFeatures::all())
        .validate_all(bytes)
        .unwrap_or_else(|e| fail(format!("invalid {label} core module: {e}")));
    let mut saw_module = false;
    for item in Parser::new(0).parse_all(bytes) {
        if let Payload::Version { encoding, .. } =
            item.unwrap_or_else(|e| fail(format!("cannot parse {label}: {e}")))
        {
            if encoding != wasmparser::Encoding::Module {
                fail(format!("{label} is not a core module"));
            }
            saw_module = true;
        }
    }
    if !saw_module {
        fail(format!("{label} has no core module header"));
    }
}

fn error_import(b: &mut ComponentBuilder) -> u32 {
    let mut ty = InstanceType::new();
    ty.export("error", ComponentTypeRef::Type(TypeBounds::SubResource)); // 0
    let ty_index = b.type_instance(Some("wasi-io-error-type"), &ty);
    let instance = b.import(
        "wasi:io/error@0.2.8",
        ComponentTypeRef::Instance(ty_index),
    );
    b.alias_export(instance, "error", ComponentExportKind::Type)
}

fn streams_import(b: &mut ComponentBuilder, error: u32) -> (u32, u32, u32) {
    let mut ty = InstanceType::new();
    ty.alias(Alias::Outer {
        kind: ComponentOuterAliasKind::Type,
        count: 1,
        index: error,
    }); // 0
    ty.export("error", ComponentTypeRef::Type(TypeBounds::Eq(0))); // 1
    ty.ty().defined_type().own(1); // 2
    ty.ty().defined_type().variant([
        ("last-operation-failed", Some(ComponentValType::Type(2))),
        ("closed", None),
    ]); // 3
    ty.export("stream-error", ComponentTypeRef::Type(TypeBounds::Eq(3))); // 4
    ty.export("output-stream", ComponentTypeRef::Type(TypeBounds::SubResource)); // 5
    ty.ty().defined_type().borrow(5); // 6
    ty.ty().defined_type().list(PrimitiveValType::U8); // 7
    ty.ty().defined_type().result(None, Some(ComponentValType::Type(4))); // 8
    ty.ty()
        .function()
        .params([
            ("self", ComponentValType::Type(6)),
            ("contents", ComponentValType::Type(7)),
        ])
        .result(Some(ComponentValType::Type(8))); // 9
    ty.export(
        "[method]output-stream.blocking-write-and-flush",
        ComponentTypeRef::Func(9),
    );
    let ty_index = b.type_instance(Some("wasi-io-streams-type"), &ty);
    let instance = b.import(
        "wasi:io/streams@0.2.8",
        ComponentTypeRef::Instance(ty_index),
    );
    let output_stream = b.alias_export(instance, "output-stream", ComponentExportKind::Type);
    let write = b.alias_export(
        instance,
        "[method]output-stream.blocking-write-and-flush",
        ComponentExportKind::Func,
    );
    (instance, output_stream, write)
}

fn stdout_import(b: &mut ComponentBuilder, output_stream: u32) -> u32 {
    let mut ty = InstanceType::new();
    ty.alias(Alias::Outer {
        kind: ComponentOuterAliasKind::Type,
        count: 1,
        index: output_stream,
    }); // 0
    ty.export("output-stream", ComponentTypeRef::Type(TypeBounds::Eq(0))); // 1
    ty.ty().defined_type().own(1); // 2
    ty.ty()
        .function()
        .params([] as [(&str, ComponentValType); 0])
        .result(Some(ComponentValType::Type(2))); // 3
    ty.export("get-stdout", ComponentTypeRef::Func(3));
    let ty_index = b.type_instance(Some("wasi-cli-stdout-type"), &ty);
    let instance = b.import(
        "wasi:cli/stdout@0.2.8",
        ComponentTypeRef::Instance(ty_index),
    );
    b.alias_export(instance, "get-stdout", ComponentExportKind::Func)
}

fn random_import(b: &mut ComponentBuilder) -> u32 {
    let mut ty = InstanceType::new();
    ty.ty()
        .function()
        .params([] as [(&str, ComponentValType); 0])
        .result(Some(PrimitiveValType::U64.into())); // 0
    ty.export("get-random-u64", ComponentTypeRef::Func(0));
    let ty_index = b.type_instance(Some("wasi-random-type"), &ty);
    let instance = b.import(
        "wasi:random/random@0.2.8",
        ComponentTypeRef::Instance(ty_index),
    );
    b.alias_export(instance, "get-random-u64", ComponentExportKind::Func)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 8 {
        fail("usage: builder MEMORY.wasm ENV.wasm LOOM.wasm ADAPTER.wasm EVIDENCE.json OUTPUT.wasm EFFECTS LOOM=WIT ...");
    }
    let memory = read(&args[1]);
    let env_core = read(&args[2]);
    let loom = read(&args[3]);
    let adapter = read(&args[4]);
    let evidence = read(&args[5]);
    let output = &args[6];
    let effects: Vec<&str> = args[7].split(',').filter(|item| !item.is_empty()).collect();
    let has_io = effects.contains(&"IO");
    let has_rand = effects.contains(&"Rand");
    if effects.iter().any(|item| !matches!(*item, "IO" | "Rand" | "Alloc")) {
        fail("effect list is outside the closed IO,Rand,Alloc set");
    }
    let exports: Vec<(&str, &str)> = args[8..]
        .iter()
        .map(|item| item.split_once('=').unwrap_or_else(|| fail("export mapping must be LOOM=WIT")))
        .collect();
    if exports.is_empty() {
        fail("at least one export mapping is required");
    }
    for (label, bytes) in [
        ("canonical-memory", &memory),
        ("effect-env", &env_core),
        ("loom-linked-core", &loom),
        ("loom-adapter", &adapter),
    ] {
        validate_core(label, bytes);
    }

    let mut b = ComponentBuilder::default();
    let memory_module = b.core_module_raw(Some("canonical-memory"), &memory);
    let memory_instance = b.core_instantiate(Some("canonical-memory"), memory_module, []);
    let canonical_memory = b.core_alias_export(
        Some("canonical-memory"), memory_instance, "memory", ExportKind::Memory,
    );
    let canonical_namespace = b.core_instantiate_exports(
        Some("canonical"), [("memory", ExportKind::Memory, canonical_memory)],
    );

    let mut output_stream_type = None;
    let mut get_stdout_core = None;
    let mut write_core = None;
    let mut drop_output_core = None;
    if has_io {
        let error = error_import(&mut b);
        let (_, output_stream, write) = streams_import(&mut b, error);
        let get_stdout = stdout_import(&mut b, output_stream);
        output_stream_type = Some(output_stream);
        get_stdout_core = Some(b.lower_func(Some("get-stdout"), get_stdout, []));
        write_core = Some(b.lower_func(
            Some("blocking-write-and-flush"),
            write,
            [CanonicalOption::Memory(canonical_memory)],
        ));
        drop_output_core = Some(b.resource_drop(output_stream));
    }
    let random_core = if has_rand {
        let random = random_import(&mut b);
        Some(b.lower_func(Some("get-random-u64"), random, []))
    } else {
        None
    };

    let wasi_env = match random_core {
        Some(random) => b.core_instantiate_exports(
            Some("wasi-env"), [("get_random_u64", ExportKind::Func, random)],
        ),
        None => b.core_instantiate_exports(Some("wasi-env"), []),
    };
    let env_module = b.core_module_raw(Some("effect-env"), &env_core);
    let env_instance = if has_rand {
        b.core_instantiate(
            Some("effect-env"), env_module, [("wasi", ModuleArg::Instance(wasi_env))],
        )
    } else {
        b.core_instantiate(Some("effect-env"), env_module, [])
    };
    let mut env_aliases = Vec::new();
    for (name, kind) in ENV_EXPORTS {
        let alias = b.core_alias_export(Some(name), env_instance, name, kind);
        env_aliases.push((name, kind, alias));
    }
    let env_namespace = b.core_instantiate_exports(Some("env"), env_aliases);
    let print_count = b.core_alias_export(
        Some("print-count"), env_instance, "print_count", ExportKind::Func,
    );
    let print_at = b.core_alias_export(
        Some("print-at"), env_instance, "print_at", ExportKind::Func,
    );
    let clear_prints = b.core_alias_export(
        Some("clear-prints"), env_instance, "clear_prints", ExportKind::Func,
    );
    let envlog_namespace = b.core_instantiate_exports(
        Some("envlog"),
        [
            ("print_count", ExportKind::Func, print_count),
            ("print_at", ExportKind::Func, print_at),
            ("clear_prints", ExportKind::Func, clear_prints),
        ],
    );

    let loom_module = b.core_module_raw(Some("loom-linked-core"), &loom);
    let loom_instance = b.core_instantiate(
        Some("loom-linked-core"), loom_module, [("env", ModuleArg::Instance(env_namespace))],
    );
    let memory_alias = b.core_alias_export(
        Some("loom-memory"), loom_instance, "memory", ExportKind::Memory,
    );
    let mut loom_aliases = vec![("memory", ExportKind::Memory, memory_alias)];
    for name in BRIDGE_EXPORTS {
        let alias = b.core_alias_export(Some(name), loom_instance, name, ExportKind::Func);
        loom_aliases.push((name, ExportKind::Func, alias));
    }
    for (loom_name, _) in &exports {
        let alias = b.core_alias_export(Some(loom_name), loom_instance, loom_name, ExportKind::Func);
        loom_aliases.push((loom_name, ExportKind::Func, alias));
    }
    let loom_namespace = b.core_instantiate_exports(Some("loom"), loom_aliases);

    let wasi_adapter = if has_io {
        b.core_instantiate_exports(
            Some("wasi-adapter"),
            [
                ("get_stdout", ExportKind::Func, get_stdout_core.unwrap()),
                ("blocking_write_and_flush", ExportKind::Func, write_core.unwrap()),
                ("drop_output_stream", ExportKind::Func, drop_output_core.unwrap()),
            ],
        )
    } else {
        b.core_instantiate_exports(Some("wasi-adapter"), [])
    };
    let adapter_module = b.core_module_raw(Some("loom-effect-adapter"), &adapter);
    let mut adapter_args = vec![
        ("loom", ModuleArg::Instance(loom_namespace)),
        ("canonical", ModuleArg::Instance(canonical_namespace)),
        ("envlog", ModuleArg::Instance(envlog_namespace)),
    ];
    if has_io {
        adapter_args.push(("wasi", ModuleArg::Instance(wasi_adapter)));
    }
    let adapter_instance = b.core_instantiate(Some("loom-effect-adapter"), adapter_module, adapter_args);
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
                CanonicalOption::Memory(canonical_memory),
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
        name: Cow::Borrowed("loom.effectful-component-adapter.v1"),
        data: Cow::Borrowed(&evidence),
    });
    let component = b.finish();
    Validator::new_with_features(WasmFeatures::all())
        .validate_all(&component)
        .unwrap_or_else(|e| fail(format!("invalid final component: {e}")));
    if output_stream_type.is_some() != has_io {
        fail("internal output-stream type state mismatch");
    }
    fs::write(output, component).unwrap_or_else(|e| fail(format!("cannot write {output}: {e}")));
}
