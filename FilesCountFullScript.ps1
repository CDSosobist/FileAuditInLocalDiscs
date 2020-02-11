cls
$CURRENTDATE = (Get-Date).DateTime
$OUTFOLDER = "\\test-stah01\c$\Users\KoshelevRA\Documents\FILES_AUDIT\" #Здесь указываем шару, в которой будут складываться наши файлы
$SuccesFile = $OUTFOLDER + "success.txt" #Этот файл нужен для фильтрации машин, которые уже обработаны
$DONTSUCCESSFILE = $OUTFOLDER + "dontSuccess.txt" #Этот файл для списка машин, которые не удалось обработать (перезаписывается с каждым запуском)
$ALLRESULTSFILE =  $OUTFOLDER + "allRecords.csv"
$DISABLEDUSERSFILE = $OUTFOLDER + "disabledUsers.csv"
$USERSINFRGROUP = $OUTFOLDER + "usersInFrGroup.csv"
$USERSREADYTOFR = $OUTFOLDER + "usersReadyToFR.txt"
$USERSNOTREADYTOFR = $OUTFOLDER + "usersNotReadyToFr.txt"
Out-File $DONTSUCCESSFILE -Encoding utf8 #Здесь как раз перезаписываем файл dontSuccess.txt
$Headings = 'Компьютер;Пользователь;Размер файлов в документах(Mb);Размер файлов на рабочем столе(Mb);Размер файлов в контактах(Mb);Размер файлов в загрузках(Mb);Размер файлов в избранном(Mb);Размер файлов в ссылках(Mb);Размер файлов в сохраненных играх(Mb);Размер файлов в истории поиска(Mb);Размер файлов в стартовом меню(Mb)' #Здесь определяем названия наших столбцов
$OUS = Get-ADOrganizationalUnit -Filter * -Properties Description -SearchBase "OU=ЦДС,OU=Company,OU=CDS,DC=cds,DC=spb" -SearchScope OneLevel #Здесь получаем список наших OU (1 уровень вниз)
$OK = ($OUS | Measure-Object).Count
$OKP = 0
int $CKP

$SmtpServer = "post.cds.spb.ru" 
$port = 587
$Emailfrom = “InfoSec@cds.spb.ru”
$Subject = “Нарушение политики ИБ (Автоматическая рассылка)”
$Subject1 = "Необходима перезагрузка (Автоматическая рассылка)"
$Image1 = "F:\scripts\logo.png"
$Image2 = "F:\scripts\slash.png"
$Image3 = "F:\scripts\zamok.jpg"
$Image4 = "F:\scripts\lock.jpg"


foreach ($OU in $OUS) { #Запускаем их в цикл, для обработки по очереди
    $OUTFILE = $OUTFOLDER + $OU.Description + ".csv"; #Определяем имена отдельных файлов для каждого OU
    if (((Get-Content $OUTFILE) -eq $null) -or (-not (Test-Path -Path $OUTFILE))) {$Headings | Out-File $OUTFILE -Append utf8} #Если файл не существует или пуст, добавляем названия столбцов
    if (((Get-Content $ALLRESULTSFILE) -eq $null) -or (-not (Test-Path -Path $ALLRESULTSFILE))) {$Headings | Out-File $ALLRESULTSFILE -Append utf8} #Если файл не существует или пуст, добавляем названия столбцов
    if (((Get-Content $DISABLEDUSERSFILE) -eq $null) -or (-not (Test-Path -Path $DISABLEDUSERSFILE))) {$Headings | Out-File $DISABLEDUSERSFILE -Append utf8} #Если файл не существует или пуст, добавляем названия столбцов
    $COMPS = Get-ADComputer -Properties lastLogon -Filter * -SearchBase $OU.DistinguishedName; #Получаем список компьютеров в OU
    $DESCRIPTION = $OU.Description #Получаем описание OU
    $N = 0
    $M = 0
    $COMPSCOUNT = ($COMPS | Measure-Object).Count
    $OKP++
    foreach ($COMP in $COMPS) { #Запускаем их в цикл для обработки по одному
        cls
        $CKP++
        $NREMAIN = ($COMPSCOUNT - $N)
        $NREMAINMOD = $NREMAIN%10
        if (($NREMAINMOD -eq 0) -Or (($NREMAINMOD -ge 5) -and ($NREMAINMOD -le 9))) {$COMPREMAIN = "компьютеров"} elseif ($NREMAINMOD -eq 1) {$COMPREMAIN = "компьютер"} elseif (($NREMAINMOD -ge 2) -and ($NREMAINMOD -le 4)) {$COMPREMAIN = "компьютера"}
        if (($M -eq 0) -Or (($M -ge 5) -and ($M -le 9))) {$COMPSUCCESS = "профилей"} elseif ($M -eq 1) {$COMPSUCCESS = "профиль"} elseif (($M -ge 2) -and ($M -le 4)) {$COMPSUCCESS = "профиля"}
        Write-Host 'Начало:' $CURRENTDATE ', обрабатывается' $DESCRIPTION ' - ' $OKP 'из' $OK 'OU' ', компьютер - '$COMP.Name',в текущем OU осталось обработать' $NREMAIN $COMPREMAIN ',' $M $COMPSUCCESS 'обработано успешно'
        $N++
        $NOTPKB = ($COMP.Name.ToString() -notmatch "PKB" -and $COMP.Name.ToString() -notmatch "MD" -and $COMP.Name.ToString() -notmatch "NN" -and $COMP.Name.ToString() -notmatch "MEDVEDEVA") #Проверяем, не сдержит ли имя компьютера "PKB" или "MD" или "NN", для отсева их из проверки
        $COMPISUP = Test-Connection -ComputerName $COMP.dNSHostName -BufferSize 32 -Count 1 -Quiet #Проверяем, доступен ли компьютер
        $IsNotSuccess = $COMP.Name.ToString() -notin (Get-Content $SuccesFile) #Проверяем, не обрабатывался ли он до этого
        if ($COMPISUP -And $NOTPKB -And $IsNotSuccess) { #Если все true - запускаем обработку
            $PROFSTRING = '\\' + $COMP.Name.ToString() + '\C$\Users'; #Определяем месторасположение профилей пользователей
            $PROFILES = Get-ChildItem $PROFSTRING -Exclude "Public","tse","User","localuser","yara","monte" #Получаем профили за исключением фильтра
            foreach ($PROFILE in $PROFILES) { #Запускаем их в цикл для обработки по одному
                $TMPCONTROL = Get-ChildItem -LiteralPath ($PROFILE.FullName + "\AppData\Local") -Filter "Temp" #Получаем папку Temp для контроля даты ее последнего изменения
                if ($TMPCONTROL.LastWriteTime -gt ((Get-Date).AddDays(-21))) { #Если не раньше 21 дня обрабатываем
                    $PROFUSER = Get-ADUser -Identity $PROFILE.Name -Properties enabled, mail, Memberof
                    $PROFUSERNAME = $PROFUSER.Name; #Получаем ФИО владельца профиля (для красоты)
                    $PROFUSERGIVENNAME = $PROFUSER.GivenName; #Получаем имя владельца профиля (для рассылки)
                    $PROFUSERISENABLED = $PROFUSER.Enabled
                    $GROUPFR = "CN=cds_folder_redirection_members,OU=Security,OU=Groups,OU=Infrastructures,OU=CDS,DC=cds,DC=spb"
                    #$PROFUSERINFRGROUP = $GROUPFR -in $PROFUSER.MemberOf
                    $PREMEMBER = "(member:1.2.840.113556.1.4.1941:=" + $PROFUSER.DistinguishedName + ")"
                    $PROFUSERINFRGROUP = $GROUPFR -in (Get-ADgroup -LDAPFilter $PREMEMBER).DistinguishedName
                    write-host "Пользователь: " $PROFUSERNAME ", в группе: " $PROFUSERINFRGROUP
                    $DOCSPATH = $PROFILE.FullName.ToString() + "\Documents"; #Указываем месторасположение "Моих документов"
                    $DESKTOPPATH = $PROFILE.FullName.ToString() + "\DESKTOP"; #Рабочего стола
                    $CONTACTSPATH = $PROFILE.FullName.ToString() + "\CONTACTS"; #Контактов
                    $DOWNLOADSPATH = $PROFILE.FullName.ToString() + "\DOWNLOADS"; #Загрузок
                    $FAVORITESPATH = $PROFILE.FullName.ToString() + "\FAVORITES"; #Избранного
                    $LINKSPATH = $PROFILE.FullName.ToString() + "\LINKS"; #Ссылок
                    $SAVEDGAMESPATH = $PROFILE.FullName.ToString() + "\SAVED GAMES"; #Сохраненных игр
                    $SEARCHESPATH = $PROFILE.FullName.ToString() + "\SEARCHES"; #Истории поиска
                    $STARTMENUPATH = $PROFILE.FullName.ToString() + "\START MENU"; #Стартового меню

                    if ($PROFUSERINFRGROUP)
                      {
                          $PROFUSER.Name | Out-File $USERSINFRGROUP -Append utf8
                      } else {

                    #Работаем с "Моими документами"
                    $FILEINDOCS = Get-ChildItem $DOCSPATH -Recurse -File #Получаем список всех файлов
                    $FILEINDOCSSIZE = ($FILEINDOCS | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum /1MB #Их размер в Mb
                    $FILEINDOCSSIZE_ROUND = [math]::Round($FILEINDOCSSIZE) #Округляем размер до последнего целого (меньше единицы будет отображаться как ноль)
                    Write-Host "Документов - " $FILEINDOCS.Count ", размер - " $FILEINDOCSSIZE_ROUND
                    #Работаем с рабочим столом
                    $FILEINDESKTOP = Get-ChildItem $DESKTOPPATH -Recurse -File #Получаем список всех файлов
                    $FILEINDESKTOPSIZE = ($FILEINDESKTOP | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum /1MB #Их размер в Mb
                    $FILEINDESKTOPSIZE_ROUND = [math]::Round($FILEINDESKTOPSIZE) #Округляем размер до последнего целого (меньше единицы будет отображаться как ноль)
                    Write-Host "Рабочий стол - " $FILEINDESKTOP.Count ", размер - " $FILEINDESKTOPSIZE_ROUND
                    #Работаем с контактами
                    $FILEINCONTACTS = Get-ChildItem $CONTACTSPATH -Recurse -File #Получаем список всех файлов
                    $FILEINCONTACTSSIZE = ($FILEINCONTACTS | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum /1MB #Их размер в Mb
                    $FILEINCONTACTSSIZE_ROUND = [math]::Round($FILEINCONTACTSSIZE) #Округляем размер до последнего целого (меньше единицы будет отображаться как ноль)
                    #Работаем с загрузками
                    $FILEINDOWNLOADS = Get-ChildItem $DOWNLOADSPATH -Recurse -File #Получаем список всех файлов
                    $FILEINDOWNLOADSSIZE = ($FILEINDOWNLOADS | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum /1MB #Их размер в Mb
                    $FILEINDOWNLOADSSIZE_ROUND = [math]::Round($FILEINDOWNLOADSSIZE) #Округляем размер до последнего целого (меньше единицы будет отображаться как ноль)
                    Write-Host "Загрузки - " $FILEINDOWNLOADS.Count ", размер - " $FILEINDOWNLOADSSIZE_ROUND
                    #Работаем с избранным
                    $FILEINFAVORITES = Get-ChildItem $FAVORITESPATH -Recurse -File #Получаем список всех файлов
                    $FILEINFAVORITESSIZE = ($FILEINFAVORITES | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum /1MB #Их размер в Mb
                    $FILEINFAVORITESSIZE_ROUND = [math]::Round($FILEINFAVORITESSIZE) #Округляем размер до последнего целого (меньше единицы будет отображаться как ноль)
                    #Работаем со ссылками
                    $FILEINLINKS = Get-ChildItem $LINKSPATH -Recurse -File #Получаем список всех файлов
                    $FILEINLINKSSIZE = ($FILEINLINKS | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum /1MB #Их размер в Mb
                    $FILEINLINKSSIZE_ROUND = [math]::Round($FILEINLINKSSIZE) #Округляем размер до последнего целого (меньше единицы будет отображаться как ноль)
                    #Работаем с сохраненными играми
                    $FILEINSAVEDGAMES = Get-ChildItem $SAVEDGAMESPATH -Recurse -File #Получаем список всех файлов
                    $FILEINSAVEDGAMESSIZE = ($FILEINSAVEDGAMES | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum /1MB #Их размер в Mb
                    $FILEINSAVEDGAMESSIZE_ROUND = [math]::Round($FILEINSAVEDGAMESSIZE) #Округляем размер до последнего целого (меньше единицы будет отображаться как ноль)
                    #Работаем с историей поиска
                    $FILEINSEARCHES = Get-ChildItem $SEARCHESPATH -Recurse -File #Получаем список всех файлов
                    $FILEINSEARCHESSIZE = ($FILEINSEARCHES | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum /1MB #Их размер в Mb
                    $FILEINSEARCHESSIZE_ROUND = [math]::Round($FILEINSEARCHESSIZE) #Округляем размер до последнего целого (меньше единицы будет отображаться как ноль)
                    #Работаем со стартовым меню
                    $FILEINSTARTMENU = Get-ChildItem $STARTMENUPATH -Recurse -File #Получаем список всех файлов
                    $FILEINSTARTMENUSIZE = ($FILEINSTARTMENU | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum /1MB #Их размер в Mb
                    $FILEINSTARTMENUSIZE_ROUND = [math]::Round($FILEINSTARTMENUSIZE) #Округляем размер до последнего целого (меньше единицы будет отображаться как ноль)

                    $SIZEOFALLFILES = $FILEINDOCSSIZE_ROUND + $FILEINDESKTOPSIZE_ROUND + $FILEINCONTACTSSIZE_ROUND + $FILEINDOWNLOADSSIZE_ROUND + $FILEINFAVORITESSIZE_ROUND + $FILEINLINKSSIZE_ROUND + $FILEINSAVEDGAMESSIZE_ROUND + $FILEINSEARCHESSIZE_ROUND + $FILEINSTARTMENUSIZE_ROUND
                    
                    if($PROFUSERISENABLED -and ($SIZEOFALLFILES -gt 800)) {
                            #Добавляем строку со всей этой инфой в целевой файл:
                            $COMP.Name + ';' + $PROFUSERNAME + ';' + $FILEINDOCSSIZE_ROUND + ';' + $FILEINDESKTOPSIZE_ROUND + ';' + $FILEINCONTACTSSIZE_ROUND + ';' + $FILEINDOWNLOADSSIZE_ROUND + ';' + $FILEINFAVORITESSIZE_ROUND + ';' + $FILEINLINKSSIZE_ROUND + ';' + $FILEINSAVEDGAMESSIZE_ROUND + ';' + $FILEINSEARCHESSIZE_ROUND + ';' + $FILEINSTARTMENUSIZE_ROUND | Out-File $OUTFILE -Append utf8;
                            $COMP.Name + ';' + $PROFUSERNAME + ';' + $FILEINDOCSSIZE_ROUND + ';' + $FILEINDESKTOPSIZE_ROUND + ';' + $FILEINCONTACTSSIZE_ROUND + ';' + $FILEINDOWNLOADSSIZE_ROUND + ';' + $FILEINFAVORITESSIZE_ROUND + ';' + $FILEINLINKSSIZE_ROUND + ';' + $FILEINSAVEDGAMESSIZE_ROUND + ';' + $FILEINSEARCHESSIZE_ROUND + ';' + $FILEINSTARTMENUSIZE_ROUND | Out-File $ALLRESULTSFILE -Append utf8;
                            $PROFUSER.sAMAccountName | Out-File $USERSNOTREADYTOFR -Append utf8;
                            $COMP.Name.ToString() | Out-File $SuccesFile -Append utf8; #Добавляем имя обработанного компьютера в контрольный файл
                            $M++
                            #В случае превышения размера хранимых файлов посылаем письмо счастья
                            $SIZEOFALLFILESMESSAGE = ""
                            $MAILNEED = 0
                            $EmailTo = 'koshelevra@cds.spb.ru'

                            if($FILEINDOCSSIZE_ROUND -gt 100) {$SIZEOFALLFILESMESSAGE = $SIZEOFALLFILESMESSAGE + " " + $FILEINDOCSSIZE_ROUND + ' мегабайт в папке "Мои документы";'; $MAILNEED = 1}
                            if($FILEINDESKTOPSIZE_ROUND -gt 100) {$SIZEOFALLFILESMESSAGE = $SIZEOFALLFILESMESSAGE + " " + $FILEINDESKTOPSIZE_ROUND + ' мегабайт на рабочем столе;'; $MAILNEED = 1}
                            if($FILEINCONTACTSSIZE_ROUND -gt 100) {$SIZEOFALLFILESMESSAGE = $SIZEOFALLFILESMESSAGE + " " + $FILEINCONTACTSSIZE_ROUND + ' мегабайт в Контактах;'; $MAILNEED = 1}
                            if($FILEINDOWNLOADSSIZE_ROUND -gt 100) {$SIZEOFALLFILESMESSAGE = $SIZEOFALLFILESMESSAGE + " " + $FILEINDOWNLOADSSIZE_ROUND + ' мегабайт в папке "Загрузки";'; $MAILNEED = 1}
                            if($FILEINFAVORITESSIZE_ROUND -gt 100) {$SIZEOFALLFILESMESSAGE = $SIZEOFALLFILESMESSAGE + " " + $FILEINFAVORITESSIZE_ROUND + ' мегабайт в Избранном;'; $MAILNEED = 1}
                            if($FILEINLINKSSIZE_ROUND -gt 100) {$SIZEOFALLFILESMESSAGE = $SIZEOFALLFILESMESSAGE + " " + $FILEINLINKSSIZE_ROUND + ' мегабайт в Ссылках;'; $MAILNEED = 1}
                            if($FILEINSAVEDGAMESSIZE_ROUND -gt 100) {$SIZEOFALLFILESMESSAGE = $SIZEOFALLFILESMESSAGE + " " + $FILEINSAVEDGAMESSIZE_ROUND + ' мегабайт в сохраненных играх;'; $MAILNEED = 1}
                            if($FILEINSEARCHESSIZE_ROUND -gt 100) {$SIZEOFALLFILESMESSAGE = $SIZEOFALLFILESMESSAGE + " " + $FILEINSEARCHESSIZE_ROUND + ' мегабайт в истории поиска;'; $MAILNEED = 1}
                            if($FILEINSTARTMENUSIZE_ROUND -gt 100) {$SIZEOFALLFILESMESSAGE = $SIZEOFALLFILESMESSAGE + " " + $FILEINSTARTMENUSIZE_ROUND + ' мегабайт в стартовом меню;'; $MAILNEED = 1}

                            $body = '<html>
                                        <head>
                                            <title></title>
                                        </head>
                                        <body>
                                            <table border="0" cellpadding="0" cellspacing="0" style="width:757px;" width="0">
                                                <tbody>
                                                    <tr>
                                                        <td style="width:722px;">
                                                            <p style="text-align: right;">
                                                                <img alt="ЦДС - строим для жизни" height="45" src="cid:att1" style="height: 0.468in; width: 2.208in;" width="212" />
                                                            </p>
                                                            <p style="font-size:20pt">
                                                                <font face="calibri">
                                                                    <img hspace="12" alt="1" height="81" src="cid:att2" width="105" />
                                                                        <strong>
                                                                            ИНЦИДЕНТ ИНФОРМАЦИОННОЙ БЕЗОПАСНОСТИ
                                                                        </strong>
                                                                </font>
                                                            </p>
                                                            <p>&nbsp;</p>
                                                            <p>
                                                                <img align="left" height="259" hspace="12" src="cid:att3" style="height:2.697in;width:3.604in;" width="346" />
                                                            </p>
                                                            <p style="text-align: center; font-size:20pt">
                                                                <font face="calibri">
                                                                    <strong>
                                                                        ' + $PROFUSERGIVENNAME + ', добрый день!
                                                                    </strong>
                                                                </font>
                                                            </p>
                                                            <p style="text-align: justify; font-size:13pt">
                                                                <font face="calibri">
                                                                    В ходе автоматического аудита соблюдения 
                                                                        <strong>
                                                                            &laquo;Правил хранения файлов и электронных документов ООО &laquo;ЦДС&raquo;
                                                                        </strong>
                                                                    было установлено, что в вашем профиле на локальных дисках рабочей станции ' + $COMP.Name.ToString() + ' хранятся корпоративные файлы в количестве: ' + $SIZEOFALLFILESMESSAGE.Substring(0, $SIZEOFALLFILESMESSAGE.Length-1)  + '.
                                                                    В данном случае происходит нарушение пункта 3.2 вышеуказанных Правил, согласно которому 
                                                                        <strong>
                                                                            создание, хранение и обмен корпоративной информацией необходимо производить только через Библиотеку документов
                                                                        </strong>
                                                                    . В виде исключения, на локальных дисках допускаются оперативные хранение и обработка файлов и документов, 
                                                                    находящихся в непосредственной обработке, с их обязательным перемещением в Библиотеку документов в конце рабочего дня.
                                                                </font>
                                                            </p>
                                                            <p style="text-align: justify; font-size:13pt">
                                                                <font face="calibri">
                                                                    В связи с этим, с целью устранения выявленных нарушений, в срок до 17:00 28.02.2020 года просим вас распределить
                                                                     находящиеся у вас в обработке и на хранении файлы и электронные документы согласно требованиям вышеуказанных Правил, 
                                                                     с последующим удалением их копий с локальных дисков ваших рабочих станций.
                                                                 </font>
                                                             </p>
                                                             <p style="text-align: justify; font-size:13pt">
                                                                <font face="calibri">
                                                                    В 19:00 28.02.2020 года будет запущен автоматический скрипт очистки локальных хранилищ рабочих станций, с удалением файлов 
                                                                    и документов, находящихся на них. Последующее восстановление удаленной информации будет возможно только при предоставлении 
                                                                    служебной записки, согласованной руководителем вашего департамента, и, в отдельных случаях, только после 
                                                                    проведения внутреннего служебного расследования инцидента информационной безопасности. Дней до запуска скрипта: <font color="red"><strong>' + ((Get-Date "28.02.2020")-(Get-Date)).Days + '</strong>

                                                                </font>
                                                             </p>
                                                             <p style="text-align: justify; font-size:13pt">
                                                                <font face="calibri">
                                                                    Для вашего удобства прикладываем <a href="file://cds.spb/Документы%20ЦДС/Регламентирующие%20документы/ДИТ/Правила_Хранение.pdf">ссылку на Правила информационной безопасности</a>
                                                                </font>
                                                             </p>
                                                             <p style="text-align: justify; font-size:13pt">
                                                                <font face="calibri">
                                                                    Спасибо за понимание!
                                                                </font>
                                                             </p>
                                                          </td>
                                                       </tr>
                                                    </tbody>
                                                 </table>
                                              </body>
                                           </html>'
                                if($MAILNEED -eq 1) {
                                    $Message = new-object Net.Mail.MailMessage
                                    Add-PSSnapin Microsoft.Exchange.Management.Powershell.Admin -erroraction silentlyContinue
                                    $att1 = new-object Net.Mail.Attachment($Image1)
                                    $att1.ContentId = "att1"
                                    $att2 = new-object Net.Mail.Attachment($Image2)
                                    $att2.ContentId = "att2"
                                    $att3 = new-object Net.Mail.Attachment($Image3)
                                    $att3.ContentId = "att3"
                                    $smtp = new-object Net.Mail.SmtpClient($SmtpServer, $port)
                                    $smtp.Credentials = New-Object System.Net.NetworkCredential("koshelevra", "zgjybcnsqvfajy1!");
                                    $Message.From = $Emailfrom
                                    $Message.To.Add($EmailTo)
                                    $Message.Subject = $Subject
                                    $Message.Body = $body
                                    $Message.IsBodyHTML = $true
                                    $Message.Attachments.Add($att1)
                                    $Message.Attachments.Add($att2)
                                    $Message.Attachments.Add($att3)
                                    $smtp.Send($Message)
                                    $att3.Dispose()
                                    $att2.Dispose()
                                    $att1.Dispose()
                                
                                }
                        } elseif(!$PROFUSERISENABLED)  {
                            $COMP.Name + ';' + $PROFUSERNAME + ';' + $FILEINDOCSSIZE_ROUND + ';' + $FILEINDESKTOPSIZE_ROUND + ';' + $FILEINCONTACTSSIZE_ROUND + ';' + $FILEINDOWNLOADSSIZE_ROUND + ';' + $FILEINFAVORITESSIZE_ROUND + ';' + $FILEINLINKSSIZE_ROUND + ';' + $FILEINSAVEDGAMESSIZE_ROUND + ';' + $FILEINSEARCHESSIZE_ROUND + ';' + $FILEINSTARTMENUSIZE_ROUND | Out-File $DISABLEDUSERSFILE -Append utf8;
                            $COMP.Name.ToString() | Out-File $SuccesFile -Append utf8; #Добавляем имя обработанного компьютера в контрольный файл
                        } else {
                            $READYLIST = Get-Content $USERSREADYTOFR
                            if ($PROFUSER.sAMAccountName -in $READYLIST) {} else {
                                $PROFUSER.sAMAccountName | Out-File $USERSREADYTOFR -Append utf8;
                            }
                        }
                    }
                }
            }
         }        $IsSuccess = $COMP.Name.ToString() -in (Get-Content $SuccesFile) #Цикл закончен, проверяем, попал ли в итоге компьютер в контрольный файл
        #Если нет - заносим его в файл с необработанными компьютерами:
        if ((-not $IsSuccess) -And $NOTPKB) {$COMP.Name + ' - ' + [datetime]::FromFileTime($COMP.lastLogon).ToString('g') | Out-File $DONTSUCCESSFILE -Append utf8}
    }
}

$READYUSERS = Get-Content -Path $USERSREADYTOFR
$NOTREADYUSERS = Get-Content -Path $USERSNOTREADYTOFR
foreach ($READYUSER in $READYUSERS)
{
  if ($READYUSER -in $NOTREADYUSERS)  {Write-Host (Get-ADUser -identity $READYUSER) " в списке не готовых!!!"} else {$READYUSER | Out-File "\\test-stah01\c$\Users\KoshelevRA\Documents\FILES_AUDIT\jeronimo.txt" -Append utf8}
}

$JERONIMO = gc -Path "\\test-stah01\c$\Users\KoshelevRA\Documents\FILES_AUDIT\jeronimo.txt"
$m = 1
foreach ($user in $JERONIMO)
{
    if ($m -ge 50) {break}

#    Add-ADGroupMember "cds_folder_redirection_members" $user
#$EmailTo1 = (Get-ADUser -Identity $user -Properties mail).mail
$EmailTo1 = "KoshelevRA@cds.spb.ru"
$body1 = '<html>
			<head>
				<title></title>
			</head>
			<body>
				<table border="0" cellpadding="0" cellspacing="0" style="width:757px;" width="0">
					<tbody>
						<tr>
							<td style="width:722px;">
								<p style="text-align: right;">
									<img alt="ЦДС - строим для жизни" height="45" src="cid:att1" style="height: 0.468in; width: 2.208in;" width="212" />
								</p>
								<p style="font-size:20pt">
									<font face="calibri">
										<img hspace="12" alt="1" height="81" src="cid:att2" width="105" />
										<strong>
											ОБНОВЛЕНИЕ ПАКЕТА БЕЗОПАСНОСТИ
										</strong>
									</font>
								</p>
								<p>&nbsp;</p>
								<p>
									<img align="left" height="259" hspace="12" src="cid:att4" style="height:2.697in;width:3.604in;" width="346" />
								</p>
								<p style="text-align: center; font-size:20pt">
									<font face="calibri">
										<strong>
											' + $PROFUSERGIVENNAME + ', добрый день!
										</strong>
									</font>
								</p>
								<p style="text-align: justify; font-size:13pt">
									<font face="calibri">
										На вашей рабочей станции были обновлены пакеты и библиотеки безопасности, для вступления в силу которых необходима 
										перезагрузка компьютера и последующая его проверка на наличие вирусов и другого вредоносного программного 
										обеспечения. В процессе проверки компьютер может несколько раз автоматически перезагрузиться.
									</font>
								</p>
								<p style="text-align: justify; font-size:13pt">
									<font face="calibri">
										В связи с этим, сегодня, ' + (Get-Date -Format D) + ', перед уходом с работы в конце рабочего дня, просим вас перезагрузить свой компьютер 
										и оставить его включенным.
									</font>
								</p>
								<p style="text-align: justify; font-size:13pt">
									<font face="calibri">
										В случае, если в указанные промежутки времени компьютер будет выключен, его проверка начнет осуществляться при первом включении, что может 
										негативно повлиять на скорость рабочего процесса.
									</font>
								</p>
								<p style="text-align: justify; font-size:13pt">
									<font face="calibri">
										Спасибо за понимание!
									</font>
								</p>
							</td>
						</tr>
					</tbody>
				</table>
			</body>
		</html>'
$Message = new-object Net.Mail.MailMessage
Add-PSSnapin Microsoft.Exchange.Management.Powershell.Admin -erroraction silentlyContinue
$att1 = new-object Net.Mail.Attachment($Image1)
$att1.ContentId = "att1"
$att2 = new-object Net.Mail.Attachment($Image2)
$att2.ContentId = "att2"
$att4 = new-object Net.Mail.Attachment($Image4)
$att4.ContentId = "att4"
$smtp = new-object Net.Mail.SmtpClient($SmtpServer, $port)
$smtp.Credentials = New-Object System.Net.NetworkCredential("koshelevra", "zgjybcnsqvfajy1!");
$Message.From = $Emailfrom
$Message.To.Add($EmailTo1)
$Message.Subject = $Subject1
$Message.Body = $body1
$Message.IsBodyHTML = $true
$Message.Attachments.Add($att1)
$Message.Attachments.Add($att2)
$Message.Attachments.Add($att4)
$smtp.Send($Message)
$att4.Dispose()
$att2.Dispose()
$att1.Dispose()
$m++
}
cls
Write-Host "Результаты выполнения задания:`nНачало:" $CURRENTDATE "`nКонец: " (Get-Date).DateTime "`nОбработано OU:" $OKP "`nОбработано компьютеров:" $CKP "`nИз них успешно:" $M
