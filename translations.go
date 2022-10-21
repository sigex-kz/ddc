package ddc

var kk map[string]string = map[string]string{
	"стр. %v из %v": "%[2]v беттің %[1]v беті",
	"Подлинник электронного документа": "Электрондық құжаттың түпнұсқасы",
	"ЭЦП, %v": "ЭСҚ, %v",
	"КАРТОЧКА ЭЛЕКТРОННОГО ДОКУМЕНТА":   "ЭЛЕКТРОНДЫҚ ҚҰЖАТТЫҢ КАРТОЧКАСЫ",
	"Дата и время формирования":         "Жасалу күні мен уақыты",
	"Информационная система или сервис": "Ақпараттық жүйе немесе сервис",
	"Содержание:":                                      "Мазмұны:",
	"Информационный блок":                              "Ақпараттық блок",
	"Визуализация электронного документа":              "Электрондық құжатты визуалдау",
	"Визуализация подписей под электронным документом": "Электрондық құжатта қол қоюды визуалдау",
	"Перечень вложенных файлов:":                       "Тіркемеленген файлдар тізімі:",
	`
При формировании карточки электронного документа была автоматически выполнена процедура проверки ЭЦП в соответствии с положениями Приказа Министра по инвестициям и развитию Республики Казахстан «Об утверждении Правил проверки подлинности электронной цифровой подписи».

Карточка электронного документа — это файл в формате PDF, состоящий из визуально отображаемой части и вложенных файлов.

Визуально отображаемая часть карточки электронного документа носит исключительно информативный характер и не обладает юридической значимостью.

Многие программы для просмотра PDF поддерживают вложенные файлы, позволяют просматривать их и сохранять как обычные файлы. Среди них Adobe Acrobat Reader и браузер Firefox.

В соответствии с Законом Республики Казахстан «Об электронном документе и электронной цифровой подписи», подлинник электронного документа обладает юридической значимостью в том случае, если он подписан ЭЦП и были выполнены проверки подписи в соответствии с утвержденными правилами.

%v

ВНИМАНИЕ! Остерегайтесь мошенников! При получении электронных документов, обязательно выполняйте проверку подписей! Злоумышленники могут пробовать подделывать или менять визуально отображаемую часть карточки,  так как она не защищена от изменения цифровой подписью.`: `
Электрондық құжат карточкасын қалыптастыру кезінде ЭСҚ тексеру рәсімі «Электрондық сандық қолтаңбаның төлнұсқалығын тексеру қағидаларын бекіту туралы» Қазақстан Республикасы Инвестициялар және даму министрінің бұйрығының ережелеріне сәйкес автоматты түрде жүзеге асырылды.

Электрондық құжат карточкасы – бұл визуалды түрде көрсетілетін бөліктен және оған қоса берілген файлдардан тұратын PDF файлы.

Электрондық құжат карточкасының визуалды көрсетілетін бөлігі тек ақпараттық мақсатта және оның заңдық мәні жоқ.

Көптеген PDF-ті қарауға арналған бағдарламалары тіркемеленген файлдарды қолдайды және оларды кәдімгі файлдар ретінде көруге және сақтауға мүмкіндік береді. Олардың ішінде Adobe Acrobat Reader және Firefox веб шолғышы бар.

Қазақстан Республикасының «Электрондық құжат және электрондық сандық қолтаңба туралы» Заңына сәйкес электрондық құжаттың түпнұсқасы ЭСҚ-мен қол қойылған және қолтаңбаны тексеру бекітілген ережелерге сәйкес жүргізілген болса, оның заңдық мәні болады.

%v

НАЗАР АУДАРЫҢЫЗ! Алаяқтардан сақ болыңыз! Электрондық құжаттарды алу кезінде міндетті түрде қолтаңбаларды тексеріңіз! Алаяқтар картаның визуалды түрде көрсетілген бөлігін қолдан жасауға немесе өзгертуге әрекеттенуі мүмкін, себебі ол сандық қолтаңба өзгертуінен қорғалмаған.`,
	"Карточка электронного документа":           "Электрондық құжат карточкасы",
	"Копия электронного документа":              "Электрондық құжаттың көшірмесі",
	"Визуализация электронной цифровой подписи": "Электрондық сандық қолтаңбаның визуалдауы",
	"Подпись №%v":                "Қолтаңба №%v",
	"Дата формирования подписи:": "Қолтаңба жасалған күн:",
	"%v, ИИН %v":                 "%v, ЖСН %v",
	"Подписал(а):":               "Қол қойды:",
	"Шаблон:":                    "Үлгі:",
	"%v, БИН %v":                 "%v, БСН %v",
	"Представляет организацию:":  "Ұйымға өкілдік етеді:",
	"Допустимое использование:":  "Рұқсат етілген пайдалану:",
	`Субъект: %v
Альтернативные имена: %v
Серийный номер: %v
С: %v
По: %v
Издатель: %v`: `Субъект: %v
Баламалы есімдер: %v
Сериялық нөмір: %v
Бастап: %v
Дейін: %v
Басып шығарушы: %v`,
	`Метка времени: %v
Субъект: %v
Серийный номер: %v
Издатель: %v`: `Уақыт белгісі: %v
Субъект: %v
Сериялық нөмір: %v
Басып шығарушы: %v`,
	`OCSP: %v
Сформирован: %v
Субъект: %v
Серийный номер: %v
Издатель: %v`: `OCSP: %v
Қалыптасты: %v
Субъект: %v
Сериялық нөмір: %v
Басып шығарушы: %v`,
}

var kkRU map[string]string = map[string]string{
	"стр. %v из %v": "%[2]v беттің %[1]v беті / стр. %[1]v из %[2]v",
	"Подлинник электронного документа": "Электрондық құжаттың түпнұсқасы / Подлинник электронного документа",
	"ЭЦП, %v": "ЭСҚ / ЭЦП, %v",
	"КАРТОЧКА ЭЛЕКТРОННОГО ДОКУМЕНТА":   "ЭЛЕКТРОНДЫҚ ҚҰЖАТТЫҢ КАРТОЧКАСЫ\nКАРТОЧКА ЭЛЕКТРОННОГО ДОКУМЕНТА",
	"Дата и время формирования":         "Жасалу күні мен уақыты\nДата и время формирования",
	"Информационная система или сервис": "Ақпараттық жүйе немесе сервис\nИнформационная система или сервис",
	"Содержание:":                                      "Мазмұны / Содержание:",
	"Информационный блок":                              "Ақпараттық блок / Информационный блок",
	"Визуализация электронного документа":              "Электрондық құжатты визуалдау / Визуализация электронного документа",
	"Визуализация подписей под электронным документом": "Электрондық құжатта қол қоюды визуалдау / Визуализация подписей под электронным документом",
	"Перечень вложенных файлов:":                       "Тіркемеленген файлдар тізімі / Перечень вложенных файлов:",
	`
При формировании карточки электронного документа была автоматически выполнена процедура проверки ЭЦП в соответствии с положениями Приказа Министра по инвестициям и развитию Республики Казахстан «Об утверждении Правил проверки подлинности электронной цифровой подписи».

Карточка электронного документа — это файл в формате PDF, состоящий из визуально отображаемой части и вложенных файлов.

Визуально отображаемая часть карточки электронного документа носит исключительно информативный характер и не обладает юридической значимостью.

Многие программы для просмотра PDF поддерживают вложенные файлы, позволяют просматривать их и сохранять как обычные файлы. Среди них Adobe Acrobat Reader и браузер Firefox.

В соответствии с Законом Республики Казахстан «Об электронном документе и электронной цифровой подписи», подлинник электронного документа обладает юридической значимостью в том случае, если он подписан ЭЦП и были выполнены проверки подписи в соответствии с утвержденными правилами.

%v

ВНИМАНИЕ! Остерегайтесь мошенников! При получении электронных документов, обязательно выполняйте проверку подписей! Злоумышленники могут пробовать подделывать или менять визуально отображаемую часть карточки,  так как она не защищена от изменения цифровой подписью.`: `
Электрондық құжат карточкасын қалыптастыру кезінде ЭСҚ тексеру рәсімі «Электрондық сандық қолтаңбаның төлнұсқалығын тексеру қағидаларын бекіту туралы» Қазақстан Республикасы Инвестициялар және даму министрінің бұйрығының ережелеріне сәйкес автоматты түрде жүзеге асырылды.

При формировании карточки электронного документа была автоматически выполнена процедура проверки ЭЦП в соответствии с положениями Приказа Министра по инвестициям и развитию Республики Казахстан «Об утверждении Правил проверки подлинности электронной цифровой подписи».

Электрондық құжат карточкасы – бұл визуалды түрде көрсетілетін бөліктен және оған қоса берілген файлдардан тұратын PDF файлы.

Карточка электронного документа — это файл в формате PDF, состоящий из визуально отображаемой части и вложенных файлов.

Электрондық құжат карточкасының визуалды көрсетілетін бөлігі тек ақпараттық мақсатта және оның заңдық мәні жоқ.

Визуально отображаемая часть карточки электронного документа носит исключительно информативный характер и не обладает юридической значимостью.

Көптеген PDF-ті қарауға арналған бағдарламалары тіркемеленген файлдарды қолдайды және оларды кәдімгі файлдар ретінде көруге және сақтауға мүмкіндік береді. Олардың ішінде Adobe Acrobat Reader және Firefox веб шолғышы бар.

Многие программы для просмотра PDF поддерживают вложенные файлы, позволяют просматривать их и сохранять как обычные файлы. Среди них Adobe Acrobat Reader и браузер Firefox.

Қазақстан Республикасының «Электрондық құжат және электрондық сандық қолтаңба туралы» Заңына сәйкес электрондық құжаттың түпнұсқасы ЭСҚ-мен қол қойылған және қолтаңбаны тексеру бекітілген ережелерге сәйкес жүргізілген болса, оның заңдық мәні болады.

В соответствии с Законом Республики Казахстан «Об электронном документе и электронной цифровой подписи», подлинник электронного документа обладает юридической значимостью в том случае, если он подписан ЭЦП и были выполнены проверки подписи в соответствии с утвержденными правилами.

%v

НАЗАР АУДАРЫҢЫЗ! Алаяқтардан сақ болыңыз! Электрондық құжаттарды алу кезінде міндетті түрде қолтаңбаларды тексеріңіз! Алаяқтар картаның визуалды түрде көрсетілген бөлігін қолдан жасауға немесе өзгертуге әрекеттенуі мүмкін, себебі ол сандық қолтаңба өзгертуінен қорғалмаған.

ВНИМАНИЕ! Остерегайтесь мошенников! При получении электронных документов, обязательно выполняйте проверку подписей! Злоумышленники могут пробовать подделывать или менять визуально отображаемую часть карточки,  так как она не защищена от изменения цифровой подписью.`,
	"Карточка электронного документа":           "Электрондық құжат карточкасы / Карточка электронного документа",
	"Копия электронного документа":              "Копия электронного документа",
	"Визуализация электронной цифровой подписи": "Электрондық сандық қолтаңбаның визуалдауы / Визуализация ЭЦП",
	"Подпись №%v":                "Қолтаңба / Подпись №%v",
	"Дата формирования подписи:": "Қолтаңба жасалған күн / Дата формирования подписи:",
	"%v, ИИН %v":                 "%v, ЖСН / ИИН %v",
	"Подписал(а):":               "Қол қойды / Подписал(а):",
	"Шаблон:":                    "Үлгі / Шаблон:",
	"%v, БИН %v":                 "%v, БСН / БИН %v",
	"Представляет организацию:":  "Ұйымға өкілдік етеді / Представляет организацию:",
	"Допустимое использование:":  "Рұқсат етілген пайдалану / Допустимое использование:",
	`Субъект: %v
Альтернативные имена: %v
Серийный номер: %v
С: %v
По: %v
Издатель: %v`: `Субъект: %v
Баламалы есімдер / Альтернативные имена: %v
Сериялық нөмір / Серийный номер: %v
Бастап / С: %v
Дейін / По: %v
Басып шығарушы / Издатель: %v`,
	`Метка времени: %v
Субъект: %v
Серийный номер: %v
Издатель: %v`: `Уақыт белгісі / Метка времени: %v
Субъект: %v
Сериялық нөмір / Серийный номер: %v
Басып шығарушы / Издатель: %v`,
	`OCSP: %v
Сформирован: %v
Субъект: %v
Серийный номер: %v
Издатель: %v`: `OCSP: %v
Қалыптасты / Сформирован: %v
Субъект: %v
Сериялық нөмір / Серийный номер: %v
Басып шығарушы / Издатель: %v`,
}