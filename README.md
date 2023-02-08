# CRYptoCopy

**ВНИМАНИЕ!** Данная программа предназначена ИСКЛЮЧИТЕЛЬНО для демонстрационных  целей! Используя её вы берете на себя всю ответственность за любой ущерб, обязательства или повреждения, вызванным любым функционалом данного ПО! 

## О программе

CRYptoCopy - небольшая программа (скрипт), предназначенная для бинарного копирования контейнеров ("сертификатов" / "подписей") между файловой системой и реестровым хранилищем КриптоПРО. При подобном копировании игнорируется все содержимое файлов контейнеров (за исключением имени). Если вам необходимо, например, скопировать контейнер с меткой о неэкспортируемости из файловой системы в реестр или наоборот, вы можете попробовать осуществить данное действие с помощью данной программы.

Представленный код был написан для использования на ОС Windows (7 или новее) и не предназначен для работы в иных системах!

## Функционал

![](https://i.imgur.com/ZRsY60u.png)

После запуска программы первое, что необходимо сделать - выбрать целевое хранилище контейнеров в реестре, которое будет использоваться для чтения / записи. Как правило, УКЭП хранятся в хранилище пользователя. Для получения доступа к хранилищу компьютера, необходимо запускать программу от имени администратора.  

Если программа запущена без прав администратора и вам требуется скопировать контейнер из файловой системы в реестр, то вы сможете это сделать только через создание .reg файла, запустить который будет предложено сразу после его создания.

Для создания файловой копии контейнера, хранящегося в реестре - нажмите "Копировать контейнер из реестра в ФС". Выберите необходимый контейнер и укажите папку для его сохранения. Обратите внимание, что для дальнейшего использования, а не переноса, целевая папка должна находится в корне несистемного диска и иметь имя, содержащее не более 8 символов, только лат. буквы и цифры, а так же не иметь спец. символов, за исключением "." и "-".

Если вам необходимо перенести / экспортировать все контейнеры из реестра - нажмите "Скопировать все контейнеры из реестра в ФС", после этого у вас откроется окно выбора папки, куда будут помещены файлы контейнеров. Обратите внимание, что названия папок будут содержать имя контейнера и могут не отображаться в КриптоПРО, даже если папкой для экспорта выступает несистемный диск. Для корректного отображения переименуйте необходимые папки с контейнерами (макс. 8 символов, только лат. буквы и цифры, без спец. символов, спец. символов, за исключением "." и "-").
