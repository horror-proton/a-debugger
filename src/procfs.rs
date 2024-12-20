pub struct MapInfo {
    pub address: u64,
    pub length: u64,
    pub perms: String,
    pub offset: u64,
    pub dev: String,
    pub inode: u64,
    pub path: Option<std::path::PathBuf>,
}

// TODO: Use map_files

pub fn parse_maps(proc_pid: &std::path::Path) -> Vec<MapInfo> {
    let maps = std::fs::read_to_string(proc_pid.join("maps")).unwrap();
    let mut result = Vec::new();
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let addr_s = parts.next().unwrap();
        let perms_s = parts.next().unwrap();
        let offset_s = parts.next().unwrap();
        let dev_s = parts.next().unwrap();
        let inode_s = parts.next().unwrap();
        let path_s = parts.next();

        let mut parts = addr_s.split('-');
        let start = u64::from_str_radix(parts.next().unwrap(), 16).unwrap();
        let end = u64::from_str_radix(parts.next().unwrap(), 16).unwrap();

        let offset = u64::from_str_radix(offset_s, 16).unwrap();
        let inode = u64::from_str_radix(inode_s, 10).unwrap();
        let path = if inode != 0 {
            path_s.map(std::path::PathBuf::from)
        } else {
            None
        };

        result.push(MapInfo {
            address: start,
            length: end - start,
            perms: perms_s.to_string(),
            offset,
            dev: dev_s.to_string(),
            inode,
            path,
        });
    }
    result
}
