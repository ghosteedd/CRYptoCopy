import re
import os
import sys
import winreg
import ctypes
import platform
import subprocess


if sys.platform != 'win32':
    print('Your platform not supported!')
    sys.exit(1)
try:
    key = winreg.OpenKey(winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE), 'SOFTWARE\\WOW6432Node')
    WOW6432Node = 'WOW6432Node\\'
    winreg.CloseKey(key)
    del(key)
except EnvironmentError:
    WOW6432Node = ''


# ################## EXCEPTIONS ################## #

class ArgError(Exception):
    pass


class DataConvertError(Exception):
    pass


class AdminStatusError(Exception):
    pass


class CurrentSIDError(Exception):
    pass


class CryptoKeyError(Exception):
    pass


class KeyNameParseError(CryptoKeyError):
    pass


class KeyListEmpty(CryptoKeyError):
    pass


class KeyNotFound(CryptoKeyError):
    pass


class FilesError(Exception):
    pass


class PathLengthError(FilesError):
    pass


class IsNotDirectoryError(FilesError):
    pass


class FileTypeError(FilesError):
    pass


class PathNotExists(FilesError):
    pass


class FileNotExists(FilesError):
    pass


class FileReadError(FilesError):
    pass


class FileWriteError(FilesError):
    pass


class CreateFileError(FilesError):
    pass


class CreateDirectoryError(FilesError):
    pass


class RegError(Exception):
    pass


class RegWriteError(RegError):
    pass


class RegReadError(RegError):
    pass

# ################################################ #


def _check_key_directory(path: str):
    if not isinstance(path, str):
        raise ArgError('Directory path type error!')
    if len(path) == 0:
        raise PathLengthError('Empty directory path!')
    if not os.path.exists(path):
        raise PathNotExists(f'Directory "{path}" not found!')
    if not os.path.isdir(path):
        raise IsNotDirectoryError('Directory path error!')
    if not (os.path.exists(path + '\\header.key') or os.path.exists(path + '\\name.key') or
            os.path.exists(path + '\\masks.key') or os.path.exists(path + '\\masks2.key') or
            os.path.exists(path + '\\primary.key') or os.path.exists(path + '\\primary2.key')):
        raise FileNotExists(f'"{path}" is not key directory!')
    if not os.path.exists(path + '\\header.key'):
        raise FileNotExists(f'File header.key in "{path}" not found!')
    if not os.path.exists(path + '\\name.key'):
        raise FileNotExists(f'File name.key in "{path}" not found!')
    if not os.path.exists(path + '\\masks.key'):
        raise FileNotExists(f'File masks.key in "{path}" not found!')
    if not os.path.exists(path + '\\masks2.key'):
        raise FileNotExists(f'File masks2.key in "{path}" not found!')
    if not os.path.exists(path + '\\primary.key'):
        raise os.path.exists(f'File primary.key in "{path}" not found!')
    if not os.path.exists(path + '\\primary2.key'):
        raise os.path.exists(f'File primary2.key in "{path}" not found!')


def _read_file(file_path: str):
    if not isinstance(file_path, str):
        raise ArgError('File path type error!')
    if len(file_path) == 0:
        raise PathLengthError('File path is empty!')
    if not re.search(r'\.key$', file_path):
        raise FileTypeError(f'File {os.path.basename(file_path)}')
    if not os.path.exists(file_path):
        raise PathNotExists('File not exists!')
    try:
        file = open(file_path, 'r')
        file.close()
    except PermissionError:
        raise FileReadError(f'Reading {os.path.basename(file_path)} failed!')
    try:
        with open(file_path, 'rb') as file:
            raw_data = file.read()
        return raw_data
    except Exception:
        raise FilesError(f'Reading {os.path.basename(file_path)} failed!')


def _get_sid_current_user():
    try:
        process = subprocess.Popen(['whoami', '/user'], stdout=subprocess.PIPE)
        data = process.communicate()
        if not data[0]:
            raise CurrentSIDError("No data!")
        data = data[0].decode('CP866')
        r = re.search(r'(S-.+\d)', data)
        if not r:
            raise CurrentSIDError('User SID not parsed!')
        return r.groups()[0]
    except Exception:
        raise CurrentSIDError("Getting user SID failed!")


def _get_key_name(name_key_data: bytes):
    if not isinstance(name_key_data, bytes) or len(name_key_data) < 5:
        raise ArgError('Wrong key name data!')
    try:
        name = name_key_data[4:4 + int(name_key_data[3])].decode('CP1251')
        if len(name) < 1:
            raise KeyNameParseError('Key name is empty!')
        return name
    except Exception:
        raise KeyNameParseError('Parse key name failed!')


def _convert_bytes2hex(data: bytes):
    if not isinstance(data, bytes) or len(data) < 1:
        raise ArgError('Data type error!')
    result = str()
    for byte in data:
        result += hex(byte)[2:] + ','
    if len(result) > 1:
        result = result[:-1]
    else:
        raise DataConvertError()
    return result


def create_reg_file(key_path: str, file_path: str, for_user: bool = True):
    """
    Создание .reg файла для дальнейшего импорта ключа в реестровое хранилище КриптоПРО

    :param key_path: Путь до папки с ключем
    :param file_path: Путь до будующего .reg файла (вкл. его расширение)
    :param for_user: Будующее хранилице ключа (компьютер - False, пользователь - True, по-умолчанию)

    :exception ArgError: Ошибка типа аргумента key_path / file_path / for_user
    :exception PathLengthError: Ошибка длинны аргумента key_path
    :exception PathNotExists: Путь, указанный в key_path не существует
    :exception IsNotDirectoryError: Путь, указанный в key_path не является директорией
    :exception FileNotExists: Один или несклько файлов ключа не существует
    :exception FileReadError: Ошибка чтения файла ключа
    :exception FilesError: Иные ошибки чтения файла(-ов) ключа
    :exception KeyNameParseError: Ошибка парсинга файла name.key (извлечение имени ключа)
    :exception DataConvertError: Ошибка конвертации ключа в 16-тиричный формат
    :exception CurrentSIDError: Ошибка получения SID текущего пользователя
    :exception CreateFileError: Ошибка создание reg файла
    """
    if not isinstance(for_user, bool):
        raise ArgError('Param type for_user error!')
    if not isinstance(file_path, str):
        raise ArgError('Param type file_path error!')
    _check_key_directory(key_path)
    name_data = _read_file(key_path + '\\name.key')
    header_data = _read_file(key_path + '\\header.key')
    primary_data = _read_file(key_path + '\\primary.key')
    primary2_data = _read_file(key_path + '\\primary2.key')
    masks_data = _read_file(key_path + '\\masks.key')
    masks2_data = _read_file(key_path + '\\masks2.key')
    key_name = _get_key_name(name_data)
    try:
        name_data = _convert_bytes2hex(name_data)
    except DataConvertError:
        raise DataConvertError('Convert name.key failed!')
    try:
        header_data = _convert_bytes2hex(header_data)
    except DataConvertError:
        raise DataConvertError('Convert header.key failed!')
    try:
        primary_data = _convert_bytes2hex(primary_data)
    except DataConvertError:
        raise DataConvertError('Convert primary.key failed!')
    try:
        primary2_data = _convert_bytes2hex(primary2_data)
    except DataConvertError:
        raise DataConvertError('Convert primary2.key failed!')
    try:
        masks_data = _convert_bytes2hex(masks_data)
    except DataConvertError:
        raise DataConvertError('Convert masks.key failed!')
    try:
        masks2_data = _convert_bytes2hex(masks2_data)
    except DataConvertError:
        raise DataConvertError('Convert masks2.key failed!')
    if for_user:
        path = f'HKEY_LOCAL_MACHINE\\SOFTWARE\\{WOW6432Node}Crypto Pro\\Settings' \
               f'\\Users\\{_get_sid_current_user()}\\Keys\\{key_name}'
    else:
        path = f'HKEY_LOCAL_MACHINE\\SOFTWARE\\{WOW6432Node}Crypto Pro\\Settings\\Keys\\{key_name}'
    text_4_write = f'Windows Registry Editor Version 5.00\n\n' \
                   f'[{path}]\n' \
                   f'"name.key"=hex:{name_data}\n' \
                   f'"header.key"=hex:{header_data}\n' \
                   f'"primary.key"=hex:{primary_data}\n' \
                   f'"primary2.key"=hex:{primary2_data}\n' \
                   f'"masks.key"=hex:{masks_data}\n' \
                   f'"masks2.key"=hex:{masks2_data}\n'
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
        with open(file_path, 'w') as file:
            file.write(text_4_write)
    except Exception:
        raise CreateFileError('Saving reg-file failed!')


def check_admin_status():
    return ctypes.windll.shell32.IsUserAnAdmin() != 0


def _create_reg_directories():
    if not check_admin_status():
        raise AdminStatusError('You are not admin!')
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f'SOFTWARE\\{WOW6432Node}')
    winreg.CreateKey(key, 'Crypto Pro')
    winreg.CloseKey(key)
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f'SOFTWARE\\{WOW6432Node}Crypto Pro')
    winreg.CreateKey(key, 'Settings')
    winreg.CloseKey(key)
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f'SOFTWARE\\{WOW6432Node}Crypto Pro\\Settings')
    winreg.CreateKey(key, 'Users')
    winreg.CreateKey(key, 'Keys')
    winreg.CloseKey(key)
    sid = _get_sid_current_user()
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f'SOFTWARE\\{WOW6432Node}Crypto Pro\\Settings\\Users')
    winreg.CreateKey(key, sid)
    winreg.CloseKey(key)
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f'SOFTWARE\\{WOW6432Node}Crypto Pro\\Settings\\Users\\{sid}')
    winreg.CreateKey(key, 'Keys')
    winreg.CloseKey(key)


def file_to_reg(key_path: str, for_user: bool = True):
    """
    Копирование ключа из файлов в реестровое хранилище КриптоПРО. Требуются права администратора!

    :param key_path: Путь до папки с ключем
    :param for_user: Будующее хранилице ключа (компьютер - False, пользователь - True, по-умолчанию)

    :exception ArgError: Ошибка типа аргумента key_path /  for_user
    :exception PathLengthError: Ошибка длинны аргумента key_path
    :exception PathNotExists: Путь, указанный в key_path не существует
    :exception IsNotDirectoryError: Путь, указанный в key_path не является директорией
    :exception FileNotExists: Один или несклько файлов ключа не существует
    :exception FileReadError: Ошибка чтения файла ключа
    :exception FilesError: Иные ошибки чтения файла(-ов) ключа
    :exception KeyNameParseError: Ошибка парсинга файла name.key (извлечение имени ключа)
    :exception AdminStatusError: Отсутствуют права администратора
    :exception CurrentSIDError: Ошибка получения SID текущего пользователя
    :exception RegWriteError: Ошибка записи данных в реестр
    """
    if not isinstance(for_user, bool):
        raise ArgError('Param type for_user error!')
    _check_key_directory(key_path)
    _create_reg_directories()
    name_data = _read_file(key_path + '\\name.key')
    header_data = _read_file(key_path + '\\header.key')
    primary_data = _read_file(key_path + '\\primary.key')
    primary2_data = _read_file(key_path + '\\primary2.key')
    masks_data = _read_file(key_path + '\\masks.key')
    masks2_data = _read_file(key_path + '\\masks2.key')
    key_name = _get_key_name(name_data)
    if for_user:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f'SOFTWARE\\{WOW6432Node}Crypto Pro\\Settings\\Users\\'
                                                        f'{_get_sid_current_user()}\\Keys')
    else:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f'SOFTWARE\\{WOW6432Node}Crypto Pro\\Settings\\Keys')
    winreg.CreateKey(key, key_name)
    winreg.CloseKey(key)
    if for_user:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f'SOFTWARE\\{WOW6432Node}Crypto Pro\\Settings\\Users\\'
                                                        f'{_get_sid_current_user()}\\Keys\\{key_name}',
                             access=winreg.KEY_ALL_ACCESS)
    else:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f'SOFTWARE\\{WOW6432Node}Crypto Pro\\Settings\\Keys\\'
                                                        f'{key_name}',
                             access=winreg.KEY_ALL_ACCESS)
    try:
        winreg.SetValueEx(key, 'name.key', 0, winreg.REG_BINARY, name_data)
        winreg.SetValueEx(key, 'header.key', 0, winreg.REG_BINARY, header_data)
        winreg.SetValueEx(key, 'primary.key', 0, winreg.REG_BINARY, primary_data)
        winreg.SetValueEx(key, 'primary2.key', 0, winreg.REG_BINARY, primary2_data)
        winreg.SetValueEx(key, 'masks.key', 0, winreg.REG_BINARY, masks_data)
        winreg.SetValueEx(key, 'masks2.key', 0, winreg.REG_BINARY, masks2_data)
    except Exception:
        raise RegWriteError()
    winreg.CloseKey(key)


def get_key_list_in_reg(for_user: bool = True):
    """
    Получение списка ключей, хранящихся в реестре. Для типа хранилища "компьютер" необходимы права администратора!

    :param for_user: хранилище ключа (компьютер - False, пользователь - True, по-умолчанию)

    :exception ArgError: Ошибка типа аргумента for_user
    :exception RegReadError: Ошибка чтения раздела/записей реестра
    :exception CurrentSIDError: Ошибка получения SID текущего пользователя
    :exception AdminStatusError: Отсутствуют права администратора
    """
    if not isinstance(for_user, bool):
        raise ArgError('Param type for_user error!')
    try:
        if for_user:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f'SOFTWARE\\{WOW6432Node}Crypto Pro\\Settings\\Users\\'
                                                            f'{_get_sid_current_user()}\\Keys')
        else:
            if not check_admin_status():
                raise AdminStatusError('You are not admin!')
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f'SOFTWARE\\{WOW6432Node}Crypto Pro\\Settings\\Keys')
    except Exception:
        raise RegReadError('Reading registry directory failed!')
    result = list()
    i = 0
    while True:
        try:
            result.append(winreg.EnumKey(key, i))
            i += 1
        except OSError:
            break
    winreg.CloseKey(key)
    return result


def _write_binary_file(file_path: str, data: bytes):
    if not isinstance(file_path, str):
        raise ArgError('File path arg type error!')
    if not isinstance(data, bytes):
        raise ArgError('Data for save type error!')
    if len(file_path) < 1:
        raise ArgError('File path arg length error!')
    if len(data) < 1:
        raise ArgError('Data length error!')
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
        with open(file_path, 'wb') as file:
            file.write(data)
    except Exception:
        raise FileWriteError()


def reg_to_file(target_dir_path: str, key_name: str, for_user: bool = True):
    """
    Копирование ключа из реестра в файлы. Для типа хранилища "компьютер" необходимы права администратора!

    :param target_dir_path: Целевая папка в которую будет экспортирован ключ
    :param key_name: Называние целевого ключа
    :param for_user: хранилище ключа (компьютер - False, пользователь - True, по-умолчанию)

    :exception ArgError: Ошибка типа аргумента target_dir_path / key_name / for_user
    :exception RegReadError: Ошибка чтения раздела/записей реестра
    :exception AdminStatusError: Отсутствуют права администратора
    :exception KeyListEmpty: Не найдено доступных ключей
    :exception KeyNotFound: Ключ с указанным именем не найден
    :exception CryptoKeyError: Ошибка чтения ключа
    :exception FileWriteError: Ошибка записи файла ключа
    :exception CurrentSIDError: Ошибка получения SID текущего пользователя
    """
    key_list = get_key_list_in_reg(for_user)
    if len(key_list) == 0:
        raise KeyListEmpty('Keys not found or access denied!')
    if not isinstance(key_name, str):
        raise ArgError('Key name type error!')
    if len(key_name) < 1:
        raise ArgError('Key name is empty')
    key_exists = False
    for key in key_list:
        if key_name == key:
            key_exists = True
            break
    if not key_exists:
        raise KeyNotFound()
    if not isinstance(target_dir_path, str):
        raise ArgError('Target path type error!')
    if len(target_dir_path) < 1:
        raise ArgError('Target path length error!')
    try:
        os.makedirs(target_dir_path)
    except FileExistsError:
        pass
    except Exception:
        raise CreateDirectoryError()
    try:
        if for_user:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f'SOFTWARE\\{WOW6432Node}Crypto Pro\\Settings\\Users\\'
                                                            f'{_get_sid_current_user()}\\Keys\\{key_name}')
        else:
            if not check_admin_status():
                raise AdminStatusError('You are not admin!')
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f'SOFTWARE\\{WOW6432Node}Crypto Pro\\Settings\\Keys\\'
                                                            f'{key_name}')
    except Exception:
        raise RegReadError('Reading registry directory failed!')
    name_data = None
    header_data = None
    masks_data = None
    masks2_data = None
    primary_data = None
    primary2_data = None
    i = 0
    try:
        while True:
            try:
                data = winreg.EnumValue(key, i)
                i += 1
                if data[0] == 'name.key':
                    name_data = data[1]
                if data[0] == 'header.key':
                    header_data = data[1]
                if data[0] == 'masks.key':
                    masks_data = data[1]
                if data[0] == 'masks2.key':
                    masks2_data = data[1]
                if data[0] == 'primary.key':
                    primary_data = data[1]
                if data[0] == 'primary2.key':
                    primary2_data = data[1]
            except OSError:
                break
    except Exception:
        raise RegReadError('Reading registry value(s) failed!')
    winreg.CloseKey(key)
    if name_data is None or header_data is None or masks_data is None or masks2_data is None or \
       primary_data is None or primary2_data is None:
        raise CryptoKeyError('Reading key data failed!')
    if not (isinstance(name_data, bytes) and isinstance(header_data, bytes) and isinstance(masks_data, bytes) and
            isinstance(masks2_data, bytes) and isinstance(primary_data, bytes) and isinstance(primary2_data, bytes)):
        raise CryptoKeyError('Type error in key value!')
    _write_binary_file(target_dir_path + '\\name.key', name_data)
    _write_binary_file(target_dir_path + '\\header.key', header_data)
    _write_binary_file(target_dir_path + '\\masks.key', masks_data)
    _write_binary_file(target_dir_path + '\\masks2.key', masks2_data)
    _write_binary_file(target_dir_path + '\\primary.key', primary_data)
    _write_binary_file(target_dir_path + '\\primary2.key', primary2_data)


def all_keys_reg_to_file(target_dir_path: str, for_user: bool = True):
    """
    Экспорт всех ключей из реестра в файлы. Для типа хранилища "компьютер" необходимы права администратора!

    :param target_dir_path: Целевая папка в которую будут экспортированы ключи
    :param for_user: хранилище ключа (компьютер - False, пользователь - True, по-умолчанию)

    :exception ArgError: Ошибка типа аргумента target_dir_path / key_name / for_user
    :exception RegReadError: Ошибка чтения раздела/записей реестра
    :exception AdminStatusError: Отсутствуют права администратора
    :exception CreateDirectoryError: Ошибка создания директории для ключа
    :exception KeyListEmpty: Не найдено доступных ключей
    :exception KeyNotFound: Ключ с указанным именем не найден
    :exception CryptoKeyError: Ошибка чтения ключа
    :exception FileWriteError: Ошибка записи файла ключа
    :exception CurrentSIDError: Ошибка получения SID текущего пользователя
    """
    key_list = get_key_list_in_reg(for_user)
    if len(key_list) == 0:
        raise KeyListEmpty('Keys not found or access denied!')
    if not isinstance(target_dir_path, str):
        raise ArgError('Target path type error!')
    if len(target_dir_path) < 1:
        raise ArgError('Target path length error!')
    try:
        os.makedirs(target_dir_path)
    except FileExistsError:
        pass
    except Exception:
        raise CreateDirectoryError()
    for key in key_list:
        os.makedirs(target_dir_path + '\\' + key)
        reg_to_file(target_dir_path + '\\' + key, key, for_user)
