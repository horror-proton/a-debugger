use object::{self, Object, ObjectSymbol};

pub struct ElfSymbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub kind: object::SymbolKind,
    pub section: object::SymbolSection,
    pub scope: object::SymbolScope,
    pub weak: bool,
}

pub struct ElfFile {
    pub path: std::path::PathBuf,
    pub symbols: Vec<ElfSymbol>,
}

impl ElfFile {
    pub fn new(path: std::path::PathBuf) -> ElfFile {
        let symbols = elf_get_symtab(&path);
        ElfFile { path, symbols }
    }
}

pub fn elf_get_symtab(path: &std::path::Path) -> Vec<ElfSymbol> {
    // let file = std::fs::File::open(path).unwrap();
    let data = std::fs::read(path).unwrap();
    let obj = object::File::parse(&*data).unwrap();
    let symtab = obj.symbols();
    symtab
        .map(|sym| ElfSymbol {
            name: sym.name().unwrap().to_string(),
            address: sym.address(),
            size: sym.size(),
            kind: sym.kind(),
            section: sym.section(),
            scope: sym.scope(),
            weak: sym.is_weak(),
        })
        .collect()
}
