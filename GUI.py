import os
import sys
import subprocess

import tkinter as tk
import tkinter.ttk as ttk
import tkinter.messagebox
import tkinter.filedialog

import key_copy


class ContainerSelector:
    def __init__(self, hide_window: bool = False):
        self._window = tk.Toplevel()
        self._window.title('Выберите контейнер')
        self._window.resizable(False, False)
        self._window.attributes('-toolwindow', True)
        self._window.attributes('-topmost', True)
        self._window.grab_set()
        self._window.focus_set()
        self._frame_container_list = ttk.Frame(self._window)
        self._lst_container = tk.Listbox(self._frame_container_list,
                                         selectmode=tk.SINGLE,   
                                         width=40,
                                         height=10)
        self._scroll_y = ttk.Scrollbar(self._frame_container_list,
                                       orient='vertical', command=self._lst_container.yview)
        self._scroll_x = ttk.Scrollbar(self._frame_container_list,
                                       orient='horizontal', command=self._lst_container.xview)
        self._lst_container['yscrollcommand'] = self._scroll_y.set
        self._lst_container['xscrollcommand'] = self._scroll_x.set
        self._btn_ok = ttk.Button(self._window,
                                  text='Выбрать',
                                  command=self._btn_select_action)
        self._lst_container.grid(row=0, column=0)
        self._scroll_y.grid(row=0, column=1, sticky='sn')
        self._scroll_x.grid(row=1, column=0, sticky='we')
        self._frame_container_list.pack(padx=5, pady=5)
        self._btn_ok.pack(padx=5, pady=5, anchor='se')
        if hide_window:
            self._window.withdraw()
        self._selected = None

    def set_list(self, container_list: list):
        if not isinstance(container_list, list):
            return None
        for container in container_list:
            self._lst_container.insert(0, container)
        self._window.deiconify()

    def wait_result(self):
        self._window.wait_window()

    def get_selected(self):
        return self._selected

    def _btn_select_action(self):
        try:
            self._selected = self._lst_container.get(self._lst_container.curselection())
        except Exception:
            return None
        self._window.destroy()


class MainWindow:
    def __init__(self):
        self._main_window = tk.Tk()
        self._main_window.title('Копирование контейнеров КриптоПро v1.1')
        try:
            os.chdir(sys._MEIPASS)
        except Exception:
            pass
        try:
            self._main_window.iconbitmap('icon.ico')
        except Exception:
            import tempfile
            import base64
            import zlib
            icon = zlib.decompress(base64.b64decode('eJxjYGAEQgEBBiDJwZDBysAgxsDAoAHEQCEGBQaIOAg4sDIgACMUj4JRMApGwQgF/ykEAFXxQRc='))
            _, icon_path = tempfile.mkstemp()
            with open(icon_path, 'wb') as icon_file:
                icon_file.write(icon)
            self._main_window.iconbitmap(icon_path)
        self._main_window.resizable(False, False)
        try:
            self._running_as_admin = key_copy.check_admin_status()
        except key_copy.AdminStatusError:
            self._running_as_admin = False
        self._reg_type = tk.IntVar()
        self._box_reg_type = ttk.LabelFrame(self._main_window,
                                            text='Тип хранилища (реестр)')
        self._rd_user = ttk.Radiobutton(self._box_reg_type,
                                        text='Пользователь',
                                        variable=self._reg_type,
                                        value=0)
        self._rd_pc = ttk.Radiobutton(self._box_reg_type,
                                      text='Компьютер',
                                      variable=self._reg_type,
                                      value=1)
        self._reg_type.set(0)
        if not self._running_as_admin:
            self._rd_pc['state'] = tk.DISABLED
        self._rd_user.grid(padx=5, pady=5, stick='w')
        self._rd_pc.grid(padx=5, pady=5, stick='w')
        self._btn_file2reg = ttk.Button(self._main_window,
                                        text='Копировать контейнер из ФС в реестр',
                                        command=self._file2reg)
        if not self._running_as_admin:
            self._btn_file2reg['text'] = 'Копировать контейнер из ФС в файл реестра'
        self._btn_reg2file = ttk.Button(self._main_window,
                                        text='Копировать контейнер из реестра в ФС',
                                        command=self._reg2file)
        self._btn_reg2file_all = ttk.Button(self._main_window,
                                            text='Скопировать все контейнеры из реестра в ФС',
                                            command=self._reg2file_all)
        self._box_reg_type.grid(padx=5, pady=5)
        self._btn_file2reg.grid(padx=5, pady=5, stick='we')
        self._btn_reg2file.grid(padx=5, pady=5, stick='we')
        self._btn_reg2file_all.grid(padx=5, pady=5, stick='we')
        try:
            self._dir_safe_path = key_copy.get_crypto_pro_safe_directory()
        except Exception:
            self._dir_safe_path = None
        if self._dir_safe_path is not None:
            self._btn_open_dir_safe = ttk.Button(self._main_window,
                                                 text='Открыть хранилище "директория"',
                                                 command=self._open_dir_safe)
            self._btn_open_dir_safe.grid(padx=5, pady=5, stick='we')

    def run(self):
        tk.messagebox.showwarning(title='Дисклеймер',
                                  message='Данная программа предназначена ИСКЛЮЧИТЕЛЬНО для демонстрационных целей!\n'
                                          'Используя её вы берете на себя всю ответственность за любой ущерб, '
                                          'обязательства или повреждения, вызванным любым функционалом данного ПО!\n'
                                          'Для некоторого функционала программы требуются права администратора. '
                                          'Обраите внимание, что при запуске от иного пользователя будет '
                                          'использоваться его директория в реестре!')
        self._main_window.mainloop()

    @staticmethod
    def _correct_reg_file_name(path):
        file_name = os.path.basename(path)
        if file_name[-4:] != '.reg':
            path += '.reg'
        return path

    def _file2reg(self):
        directory = tkinter.filedialog.askdirectory(title='Папка с контейнером')
        if directory == '':
            return None
        if not self._running_as_admin:
            target_file = tkinter.filedialog.asksaveasfilename(title='Сохранение файла реестра',
                                                               filetypes=(('Файлы реестра (.reg)', '*.reg'),))
            if target_file == '':
                return None
            target_file = self._correct_reg_file_name(target_file)
            try:
                key_copy.create_reg_file(directory, target_file, self._reg_type.get() == 0)
            except key_copy.PathNotExists:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             message='Указанная папка не существует!')
                return None
            except key_copy.IsNotDirectoryError:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             message='Указаннаый путь не является папкой!')
                return None
            except key_copy.FileNotExists:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             message='Файл(ы) контейнера не найдены!')
                return None
            except key_copy.FileReadError:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             message='Ошибка чтения контейнера!')
                return None
            except key_copy.CreateFileError:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             message='Ошибка создания .reg файла!')
                return None
            except key_copy.FilesError:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             message='Ошибка чтения контейнера! (2)')
                return None
            except key_copy.KeyNameParseError:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             message='Ошибка чтения имени контейнера (name.key)!')
                return None
            except key_copy.DataConvertError:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             message='Ошибка конвертации ключа в 16-тиричный формат!')
                return None
            except key_copy.CurrentSIDError:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             message='Ошибка получения SID текущего пользователя!')
                return None
            except Exception:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             message='Ошибка копирования контейнера!')
                return None
            answer = tkinter.messagebox.askyesno(title='Успех',
                                                 message='Файл реестра с контейнером успешно создан. Хотите внести '
                                                         'изменения из данного файла в реестр?')
            if answer:
                try:
                    subprocess.Popen(['regedit.exe', target_file], shell=True)
                except Exception:
                    tkinter.messagebox.showerror(title='Ошибка!', message='Не удалось импортировать файл в реестр!')
                    return None
        else:
            try:
                key_copy.file_to_reg(directory, self._reg_type.get() == 0)
            except key_copy.PathNotExists:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             message='Указанная папка не существует!')
                return None
            except key_copy.IsNotDirectoryError:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             message='Указаннаый путь не является папкой!')
                return None
            except key_copy.FileNotExists:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             message='Файл(ы) контейнера не найдены!')
                return None
            except key_copy.FileReadError:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             message='Ошибка чтения контейнера!')
                return None
            except key_copy.FilesError:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             message='Ошибка чтения контейнера! (2)')
                return None
            except key_copy.KeyNameParseError:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             message='Ошибка чтения имени контейнера (name.key)!')
                return None
            except key_copy.DataConvertError:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             message='Ошибка конвертации ключа в 16-тиричный формат!')
                return None
            except key_copy.CurrentSIDError:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             message='Ошибка получения SID текущего пользователя!')
                return None
            except key_copy.AdminStatusError:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             message='Отсутствуют права администратора!')
                return None
            except key_copy.RegWriteError:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             message='Ошибка записи данных в реестр!')
                return None
            except Exception:
                tkinter.messagebox.showerror(title='Ошибка!',
                                             text='Ошибка копирования контейнера!')
                return None
            tkinter.messagebox.showinfo(title='Успех',
                                        message='Контейнер успешно скопирован.')

    def _reg2file(self):
        try:
            container_list = key_copy.get_key_list_in_reg(self._reg_type.get() == 0)
        except key_copy.RegReadError:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Ошибка чтения раздела реестра!')
            return None
        except key_copy.AdminStatusError:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Отсутствуют права администратора!')
            return None
        except key_copy.CurrentSIDError:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Ошибка получения SID текущего пользователя!')
            return None
        except Exception:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Ошибка получения списка контейнеров!')
            return None
        if len(container_list) == 0:

            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Контейнеров не найдено!')
            return None
        container = ContainerSelector(True)
        container.set_list(container_list)
        container.wait_result()
        selected_container = container.get_selected()
        if selected_container is None:
            return None
        directory = tkinter.filedialog.askdirectory(title='Целевая папка с контейнером')
        if directory == '':
            return None
        try:
            key_copy.reg_to_file(directory, selected_container, self._reg_type.get() == 0)
        except key_copy.RegReadError:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Ошибка чтения раздела реестра!')
            return None
        except key_copy.AdminStatusError:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Отсутствуют права администратора!')
            return None
        except key_copy.KeyListEmpty:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Список контейнеров пуст!')
            return None
        except key_copy.KeyNotFound:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Указанный контейнер не найден!')
            return None
        except key_copy.CryptoKeyError:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Ошибка чтения контейнера!')
            return None
        except key_copy.FileWriteError:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Ошибка записи файла(-ов)!')
            return None
        except key_copy.CurrentSIDError:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Ошибка получения SID текущего пользователя!')
            return None
        except Exception:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Ошибка копирования контейнера!')
            return None
        tkinter.messagebox.showinfo(title='Успех',
                                    message='Контейнер успешно скопирован в ФС.')

    def _reg2file_all(self):
        try:
            container_list = key_copy.get_key_list_in_reg(self._reg_type.get() == 0)
        except key_copy.RegReadError:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Ошибка чтения раздела реестра!')
            return None
        except key_copy.AdminStatusError:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Отсутствуют права администратора!')
            return None
        except key_copy.CurrentSIDError:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Ошибка получения SID текущего пользователя!')
            return None
        except Exception:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Ошибка получения списка контейнеров!')
            return None
        if len(container_list) == 0:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Контейнеров не найдено!')
            return None
        directory = tkinter.filedialog.askdirectory(title='Целевая папка с контейнерами')
        if directory == '':
            return None
        try:
            key_copy.all_keys_reg_to_file(directory, self._reg_type.get() == 0)
        except key_copy.RegReadError:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Ошибка чтения раздела реестра!')
            return None
        except key_copy.AdminStatusError:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Отсутствуют права администратора!')
            return None
        except key_copy.KeyListEmpty:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Список контейнеров пуст!')
            return None
        except key_copy.KeyNotFound:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Указанный контейнер не найден!')
            return None
        except key_copy.CryptoKeyError:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Ошибка чтения контейнера!')
            return None
        except key_copy.CreateDirectoryError:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Ошибка создания директории для контейнера!')
            return None
        except key_copy.FileWriteError:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Ошибка записи файла(-ов)!')
            return None
        except key_copy.CurrentSIDError:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Ошибка получения SID текущего пользователя!')
            return None
        except Exception:
            tkinter.messagebox.showerror(title='Ошибка!',
                                         message='Ошибка копирования контейнеров!')
            return None
        tkinter.messagebox.showinfo(title='Успех',
                                    message='Контейнеры успешно скопированы в ФС.')

    def _open_dir_safe(self):
        tk.messagebox.showinfo(title='Напоминание',
                               message='Для корректного чтения контейнерв, имена папкок должны:\n'
                                       '* не превышать 8 символов\n'
                                       '* иметь только лат. буквы и цифры\n'
                                       '* не иметь спец. символов, за исключением "-"\n'
                                       '* заканчиваться на ".000" (данное окончание не складывается с размером имени'
                                       ' папки)')
        try:
            subprocess.Popen(['explorer.exe', self._dir_safe_path], shell=True)
        except Exception:
            tkinter.messagebox.showerror(title='Ошибка!', message='Не удалось открыть хранилище "директория"!')


if __name__ == '__main__':
    MainWindow().run()
