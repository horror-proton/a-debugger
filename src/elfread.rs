use object::{self, Object};

pub fn elf_get_symtab(path: &std::path::Path) {
    let file = std::fs::File::open(path).unwrap();
    let data = std::fs::read(path).unwrap();
    let obj = object::File::parse(&*data).unwrap();
    let symtab = obj.symbols();
    for symbol in symtab {
        println!("{:?}", symbol);
    }
}
