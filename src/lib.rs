// C library wrapper around the rust PDB crate and related useful utilities.
//
// (c) Ulf Frisk, 2023
// Author: Ulf Frisk, pcileech@frizk.net
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
//

use core::ffi::{CStr, c_char};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::path::Path;
use std::sync::Mutex;
use lazy_static::lazy_static;
use pdb::{AddressMap, FallibleIterator, ItemInformation, PDB, SymbolTable, TypeIndex};

type ResultEx<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// GLOBALS:
// accesses to G_HASHMAP must be serialized behind G_LOCK.
// accesses to individual PdbCRust are serialized behind internal lock.
// not very rust like - but C library "requires" it and it works!
static mut G_HASHMAP : Option<HashMap<usize, PdbCRust>> = None;
lazy_static! {
    static ref G_LOCK: Mutex<usize> = Mutex::new(0);
}

struct PdbCRust {
    id : usize,
    lock : Mutex<u32>,
    filename : String,
    pdb : PDB<'static, File>,
    symbol_table : SymbolTable<'static>,
    address_map : AddressMap<'static>,
    type_information : ItemInformation<'static, TypeIndex>,
}

/// Retieve a PdbCRust context struct for a given numeric handle.
/// 
/// NB! the returned PdbCRust contains a mutex named 'lock' which
/// must be locked before additional usage of this struct to avoid
/// any threading issues.
/// 
fn get_context(id : usize) -> ResultEx<&'static PdbCRust>
{
    let _lock = G_LOCK.lock();
    unsafe {
        if G_HASHMAP.is_none() {
            G_HASHMAP = Some(HashMap::new());
        }
        match G_HASHMAP.as_mut().unwrap().get(&id) {
            None => return Err("unable to retrieve context".into()),
            Some(r) => Ok(r),
        }
    }
}

/// Close a PDB numeric handle previously opened by the open() function.
/// 
fn close(id : usize) {
    let _lock = G_LOCK.lock();
    unsafe {
        if G_HASHMAP.is_some() {
            G_HASHMAP.as_mut().unwrap().remove(&id);
        }
    }
}

/// Open a PDB file for later use and return a numeric handle to it.
/// 
/// The opened PDB file should be closed by calling close() with the
/// previously returned numeric handle to avoid any memory leaks.
///
fn open(filename : &str) -> ResultEx<usize> {

    // initialize pdb functionality:
    let file = File::open(filename)?;
    let mut pdb = pdb::PDB::open(file)?;
    let symbol_table = pdb.global_symbols()?;
    let address_map = pdb.address_map()?;
    let type_information = pdb.type_information()?;

    // create struct for hashmap:
    let mut ctx = PdbCRust {
        id : 0,
        lock : Mutex::new(0),
        filename : filename.to_string(),
        pdb : pdb,
        symbol_table : symbol_table,
        address_map : address_map,
        type_information : type_information,
    };

    // atomic fetch next id and lock global map before insertion and ok!
    let mut counter = G_LOCK.lock().unwrap();
    *counter += 1;
    let id = *counter;
    ctx.id = id;
    unsafe {
        if G_HASHMAP.is_none() {
            G_HASHMAP = Some(HashMap::new());
        }
        G_HASHMAP.as_mut().unwrap().insert(ctx.id, ctx);
    }
    return Ok(id);
}

/// Fetch the symbol offset relative to the module base.
///
fn symbol_offset(id : usize, symbol_name : &str) -> ResultEx<u32>
{
    let ctx = get_context(id)?;
    let _lock = ctx.lock.lock();
    let symbol_name_raw = Some(pdb::RawString::from(symbol_name));
    let mut symbols_iter = ctx.symbol_table.iter();
    loop {
        let symbol = match symbols_iter.next()? {
            None => break,
            Some(s) => s,
        };
        let symbol_data = match symbol.parse() {
            Ok(pdb::SymbolData::Public(r)) => r,
            _ => continue,
        };
        if symbol_name_raw == Some(symbol_data.name) {
            return Ok(symbol_data.offset.to_rva(&ctx.address_map).unwrap_or_default().0);
        }
    }
    return Err("symbol_offset: not found".into());
}

/// Fetch a symbol name and displacement given the symbol offset.
///
fn symbol_name_from_offset(id : usize, symbol_offset : u32) -> ResultEx<(String, u32)>
{
    let ctx = get_context(id)?;
    let _lock = ctx.lock.lock();
    let mut symbols_iter = ctx.symbol_table.iter();
    let mut symbol_data_valid : Option<pdb::PublicSymbol> = None;
    loop {
        let symbol = match symbols_iter.next()? {
            None => break,
            Some(s) => s,
        };
        let symbol_data = match symbol.parse() {
            Ok(pdb::SymbolData::Public(r)) => r,
            _ => continue,
        };
        let symbol_rva = symbol_data.offset.to_rva(&ctx.address_map).unwrap_or_default().0;
        if symbol_rva > symbol_offset {
            break;
        }
        if symbol_rva != 0 {
            symbol_data_valid = Some(symbol_data);
        }
    }
    if symbol_data_valid == None {
        return Err("symbol_name_from_offset: not found".into());
    }
    let symbol_data = symbol_data_valid.unwrap();
    let symbol_rva = symbol_data.offset.to_rva(&ctx.address_map).unwrap_or_default().0;
    let symbol_displacement = symbol_rva - symbol_offset;
    if symbol_rva == 0 || symbol_displacement > 0x00010000 {
        return Err("symbol_name_from_offset: not found".into());
    }
    return Ok((symbol_data.name.to_string().into(), symbol_displacement));
}

/// Fetch the size of a type/struct.
///
fn type_size(id : usize, type_name : &str) -> ResultEx<u32> {
    let ctx = get_context(id)?;
    let _lock = ctx.lock.lock();
    let type_name_raw = Some(pdb::RawString::from(type_name));
    let mut types_iter = ctx.type_information.iter();
    loop {
        let typ = match types_iter.next()? {
            None => break,
            Some(s) => s,
        };
        let type_data = match typ.parse() {
            Ok(pdb::TypeData::Class(r)) => r,
            _ => continue,
        };
        if type_data.size > 0 && type_name_raw == Some(type_data.name) && type_data.size <= u32::MAX.into() {
            return Ok(type_data.size.try_into().unwrap());
        }
    }
    return Err("type_size: not found".into());
}

/// Fetch the child field offset inside a type/struct.
///
fn type_child_offset(id : usize, type_name : &str, type_child : &str) -> ResultEx<u32> {
    let ctx = get_context(id)?;
    let _lock = ctx.lock.lock();
    let type_name_raw = Some(pdb::RawString::from(type_name));
    let type_child_raw = Some(pdb::RawString::from(type_child));
    let mut type_finder = ctx.type_information.finder();
    let mut types_iter = ctx.type_information.iter();
    loop {
        let typ = match types_iter.next()? {
            None => break,
            Some(s) => s,
        };
        type_finder.update(&types_iter);    
        match typ.parse() {
            Ok(pdb::TypeData::Class(pdb::ClassType {name, fields: Some(fields), ..})) => {
                if type_name_raw != Some(name) {
                    continue;
                }
                let type_item = match type_finder.find(fields) {
                    Err(_) => continue,
                    Ok(r) => r,
                };
                let type_field_list = match type_item.parse() {
                    Ok(pdb::TypeData::FieldList(r)) => r,
                    _ => continue,
                };
                // `fields` is a Vec<TypeData>
                for field in type_field_list.fields {
                    if let pdb::TypeData::Member(member) = field {
                        if type_child_raw == Some(member.name) && member.offset <= u32::MAX.into()  {
                            return Ok(member.offset.try_into().unwrap());
                        }
                    }
                }
            },
            _ => {},
        }
    }
    return Err("type_child_offset: not found".into());
}

/// Ensure the PDB file with a specific name/guidage resides in the base_path.
///
/// If the PDB file is not found on the path it may optionally be downloaded
/// from the Microsoft symbol server and put in the path. If a download is to
/// take place it will do so in blocking mode - i.e. it may take a short time.
///
fn pdb_download_ensure(base_path : &str, pdb_guidage : &str, pdb_name : &str, is_mspdb_download : bool) -> ResultEx<String> {
    // verify base path:
    let path = Path::new(base_path);
    if !path.is_dir() {
        return Err("base path '{base_path}' is not a valid directory".into());
    }
    // verify/create pdb path:
    let path = path.join(pdb_name);
    if !path.is_dir() {
        std::fs::create_dir(&path)?;
    }
    // verify/create guid path:
    let path = path.join(pdb_guidage);
    if !path.is_dir() {
        std::fs::create_dir(&path)?;
    }
    // verify complete file path:
    // (also return success if file already exists)
    let path = path.join(pdb_name);
    let path_string = match path.to_str() {
        None => return Err("invalid file path".into()),
        Some(r) => String::from(r),
    };
    if path.is_file() {
        return Ok(path_string);
    }
    if !is_mspdb_download {
        return Err("download from ms-pdb server not enabled".into());
    }
    // test if possible to create a file in the directory:
    std::fs::File::create(&path)?;
    std::fs::remove_file(&path)?;
    // fetch pdb file from microsoft symbol server:
    let url = format!("https://msdl.microsoft.com/download/symbols/{pdb_name}/{pdb_guidage}/{pdb_name}");
    let response = reqwest::blocking::get(url)?;
    match response.content_length() {
        None => return Err("download fail".into()),
        Some(r) if r < 0x1000 => return Err("download content length too small".into()),
        Some(r) if r > 0x04000000 => return Err("download content length too large".into()),
        _ => {},
    }
    let mut file = std::fs::File::create(&path)?;
    let mut content =  std::io::Cursor::new(response.bytes()?);
    std::io::copy(&mut content, &mut file)?;
    return Ok(path_string);
}



/// Basic test harness for the PDBCRust wrapper module.
///
#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    pub fn load_pdb() {
        let pdb_file = pdb_download_ensure(std::env::temp_dir().to_str().unwrap(), "0C3FB08B9223E2EFB08FA14331050B261", "ntkrnlmp.pdb", true).unwrap();
        let id = open(&pdb_file).unwrap();
        close(id);
    }

    #[test]
    pub fn load_pdb_and_check_symbols() {
        let pdb_file = pdb_download_ensure(std::env::temp_dir().to_str().unwrap(), "BF32B9F6C843C1ACB8AD7DFF56370AFE1", "ntkrnlmp.pdb", true).unwrap();
        let id = open(&pdb_file).unwrap();
        assert_eq!(symbol_offset(id, "MmPfnDatabase").unwrap(), 5501856);
        assert_eq!(symbol_name_from_offset(id, 5501856).unwrap(), (String::from("MmPfnDatabase"), 0));
        assert_eq!(type_size(id, "_FILE_OBJECT").unwrap(), 216);
        assert_eq!(type_size(id, "_EPROCESS").unwrap(), 2136);
        assert_eq!(type_child_offset(id, "_FILE_OBJECT", "Vpb").unwrap(), 16);
        assert_eq!(type_child_offset(id, "_EPROCESS", "VadRoot").unwrap(), 1576);
        close(id);
    }
}



/// Open a PDB file for later use and return a numeric handle to it.
/// 
/// The opened PDB file should be closed by calling close() with the
/// previously returned numeric handle to avoid any memory leaks.
///
/// C-EXPORTED FUNCTION.
/// 
#[no_mangle]
pub extern "C" fn pdbcrust_open(c_filename: *const c_char) -> usize {
    let cstr = unsafe { CStr::from_ptr(c_filename) };
    match cstr.to_str() {
        Ok(filename) => {
            match open(filename) {
                Ok(r) => r,
                Err(_) => 0,
            }
        },
        Err(_) => 0,
    }
}

/// Close a PDB numeric handle previously opened by the open() function.
/// 
/// C-EXPORTED FUNCTION.
/// 
#[no_mangle]
pub extern "C" fn pdbcrust_close(handle: usize) {
    close(handle);
}

/// Fetch the symbol offset relative to the module base.
///
/// C-EXPORTED FUNCTION.
/// 
#[no_mangle]
pub extern "C" fn pdbcrust_symbol_offset(id : usize, c_symbol_name: *const c_char) -> u32 {
    let cstr = unsafe { CStr::from_ptr(c_symbol_name) };
    let symbol_name = match cstr.to_str() {
        Err(_) => return 0,
        Ok(r) => r,
    };
    match symbol_offset(id, symbol_name) {
        Err(_) => return 0,
        Ok(r) => return r,
    }
}

/// Fetch a symbol name given the symbol offset.
///
/// C-EXPORTED FUNCTION.
/// 
#[no_mangle]
pub extern "C" fn pdbcrust_symbol_name_from_offset(
    id : usize,
    symbol_offset : u32,
    len_symbol_name : usize,
    c_symbol_name: *mut c_char,
    c_symbol_deplacement: *mut i32
) -> bool {
    let symbol_name_and_displacement = match symbol_name_from_offset(id, symbol_offset) {
        Err(_) => return false,
        Ok(r) => r,
    };
    let symbol_name_cstring = match CString::new(symbol_name_and_displacement.0) {
        Err(_) => return false,
        Ok(r) => r,
    };
    let symbol_name_bytes = symbol_name_cstring.as_bytes_with_nul();
    if symbol_name_bytes.len() > len_symbol_name {
        return false;
    }
    unsafe {
        std::ptr::copy(symbol_name_bytes.as_ptr().cast(), c_symbol_name, symbol_name_bytes.len());
        *c_symbol_deplacement = symbol_name_and_displacement.1 as i32;
    }
    return true;
}

/// Fetch the size of a type/struct.
///
/// C-EXPORTED FUNCTION.
/// 
#[no_mangle]
pub extern "C" fn pdbcrust_type_size(id : usize, c_type_name: *const c_char) -> u32 {
    let cstr = unsafe { CStr::from_ptr(c_type_name) };
    let type_name = match cstr.to_str() {
        Err(_) => return 0,
        Ok(r) => r,
    };
    match type_size(id, type_name) {
        Err(_) => return 0,
        Ok(r) => return r,
    }
}

/// Fetch the child field offset inside a type/struct.
///
/// C-EXPORTED FUNCTION.
/// 
#[no_mangle]
pub extern "C" fn pdbcrust_type_child_offset(
    id : usize,
    c_type_name: *const c_char,
    c_type_child: *const c_char,
    c_child_offset: *mut u32
) -> bool {
    let cstr = unsafe { CStr::from_ptr(c_type_name) };
    let type_name = match cstr.to_str() {
        Err(_) => return false,
        Ok(r) => r,
    };
    let cstr = unsafe { CStr::from_ptr(c_type_child) };
    let type_child = match cstr.to_str() {
        Err(_) => return false,
        Ok(r) => r,
    };
    let child_offset = match type_child_offset(id, type_name, type_child) {
        Err(_) => return false,
        Ok(r) => r,
    };
    unsafe {
        *c_child_offset = child_offset;
    }
    return true;
}

/// Ensure the PDB file with a specific name/guidage resides in the base_path.
///
/// If the PDB file is not found on the path it may optionally be downloaded
/// from the Microsoft symbol server and put in the path. If a download is to
/// take place it will do so in blocking mode - i.e. it may take a short time.
///
/// C-EXPORTED FUNCTION.
/// 
#[no_mangle]
pub extern "C" fn pdbcrust_pdb_download_ensure(
    c_pdb_path : *const c_char,
    c_pdb_guidage : *const c_char,
    c_pdb_name : *const c_char,
    is_mspdb_download : bool,
    len_path_path_result : usize,
    c_pdb_path_result: *mut c_char
) -> bool {
    let cstr = unsafe { CStr::from_ptr(c_pdb_path) };
    let pdb_path = match cstr.to_str() {
        Err(_) => return false,
        Ok(r) => r,
    };
    let cstr = unsafe { CStr::from_ptr(c_pdb_guidage) };
    let pdb_guidage = match cstr.to_str() {
        Err(_) => return false,
        Ok(r) => r,
    };
    let cstr = unsafe { CStr::from_ptr(c_pdb_name) };
    let pdb_name = match cstr.to_str() {
        Err(_) => return false,
        Ok(r) => r,
    };
    let pdb_path_result_string = match pdb_download_ensure(pdb_path, pdb_guidage, pdb_name, is_mspdb_download) {
        Err(_) => return false,
        Ok(r) => r,
    };
    let pdb_path_result_cstring = match CString::new(pdb_path_result_string) {
        Err(_) => return false,
        Ok(r) => r,
    };
    let pdb_path_result_bytes = pdb_path_result_cstring.as_bytes_with_nul();
    if pdb_path_result_bytes.len() > len_path_path_result {
        return false;
    }
    unsafe {
        std::ptr::copy(pdb_path_result_bytes.as_ptr().cast(), c_pdb_path_result, pdb_path_result_bytes.len());
    }
    return true;
}
