cls
$CURRENTDATE = (Get-Date).DateTime
$OUTFOLDER = "\\test-stah01\c$\Users\KoshelevRA\Documents\FILES_AUDIT\" #Здесь указываем шару, в которой будут складываться наши файлы
$SuccesFile = $OUTFOLDER + "success.txt" #Этот файл нужен для фильтрации машин, которые уже обработаны
$DONTSUCCESSFILE = $OUTFOLDER + "dontSuccess.txt" #Этот файл для списка машин, которые не удалось обработать (перезаписывается с каждым запуском) 
Out-File $DONTSUCCESSFILE -Encoding utf8 #Здесь как раз перезаписываем файл dontSuccess.txt
$Headings = 'Компьютер;Пользователь;Папок в Документах;Файлов в Документах;Размер файлов в документах (Mb);Папок на рабочем столе;Файлов на рабочем столе;Размер файлов на рабочем столе (Mb)' #Здесь определяем названия наших столбцов
$OUS = Get-ADOrganizationalUnit -Filter * -SearchBase "OU=ЦДС,OU=Company,OU=CDS,DC=cds,DC=spb" -SearchScope OneLevel #Здесь получаем список наших OU (1 уровень вниз)
$OK = ($OUS | Measure-Object).Count
$OKP = 0
foreach ($OU in $OUS) { #Запускаем их в цикл, для обработки по очереди
    $OUTFILE = $OUTFOLDER + $OU.Name + ".csv"; #Определяем имена отдельных файлов для каждого OU
    if (((Get-Content $OUTFILE) -eq $null) -or (-not (Test-Path -Path $OUTFILE))) {$Headings | Out-File $OUTFILE -Append utf8} #Если файл не существует или пуст, добавляем названия столбцов
    $COMPS = Get-ADComputer -Properties lastLogon -Filter * -SearchBase $OU.DistinguishedName; #Получаем список компьютеров в OU
    $N = 0
    $M = 0
    $COMPSCOUNT = ($COMPS | Measure-Object).Count
    $OKP++
    foreach ($COMP in $COMPS) { #Запускаем их в цикл для обработки по одному
        cls
        $NREMAIN = ($COMPSCOUNT - $N)
        $NREMAINMOD = $NREMAIN%10
        if (($NREMAINMOD -eq 0) -Or (($NREMAINMOD -ge 5) -and ($NREMAINMOD -le 9))) {$COMPREMAIN = "компьютеров"} elseif ($NREMAINMOD -eq 1) {$COMPREMAIN = "компьютер"} elseif (($NREMAINMOD -ge 2) -and ($NREMAINMOD -le 4)) {$COMPREMAIN = "компьютера"}
        if (($M -eq 0) -Or (($M -ge 5) -and ($M -le 9))) {$COMPSUCCESS = "компьютеров"} elseif ($M -eq 1) {$COMPSUCCESS = "компьютер"} elseif (($M -ge 2) -and ($M -le 4)) {$COMPSUCCESS = "компьютера"}
        Write-Host 'Начало:' $CURRENTDATE ', обрабаытвается' $OKP 'из' $OK 'OU' ', в текущем OU осталось обработать' $NREMAIN $COMPREMAIN ',' $M $COMPSUCCESS 'обработано успешно'
        $N++
        $NOTPKB = ($COMP.Name.ToString() -notmatch "PKB") #Проверяем, не сдержит ли имя компьютера "PKB", для отсева их из проверки
        $COMPISUP = Test-Connection -ComputerName $COMP.dNSHostName -BufferSize 32 -Count 1 -Quiet #Проверяем, доступен ли компьютер
        $IsNotSuccess = $COMP.Name.ToString() -notin (Get-Content $SuccesFile) #Проверяем, не обрабатывался ли он до этого
        if ($COMPISUP -And $NOTPKB -And $IsNotSuccess) { #Если все true - запускаем обработку
            $PROFSTRING = '\\' + $COMP.Name.ToString() + '\C$\Users'; #Определяем месторасположение профилей пользователей
            $PROFILES = Get-ChildItem $PROFSTRING -Exclude "Public","tse","User","localuser","yara","monte" #Получаем профили за исключением фильтра
            foreach ($PROFILE in $PROFILES) { #Запускаем их в цикл для обработки по одному
                $TMPCONTROL = Get-ChildItem -LiteralPath ($PROFILE.FullName + "\AppData\Local") -Filter "Temp" #Получаем папку Temp для контроля даты ее последнего изменения
                if ($TMPCONTROL.LastWriteTime -gt ((Get-Date).AddDays(-21))) { #Если не раньше 21 дня - обрабатываем
                    $PROFUSERNAME = (Get-ADUser -Identity $PROFILE.Name).Name; #Получаем ФИО владельца профиля (для красоты)
                    $DOCSPATH = $PROFILE.FullName.ToString() + "\Documents"; #Указываем месторасположение "Моих документов"
                    $DESKTOPPATH = $PROFILE.FullName.ToString() + "\DESKTOP"; #И рабочего стола
                    #Работаем с "Моими документами"
                    $FOLDERSINDOCS = (Get-ChildItem $DOCSPATH -Recurse -Directory | Where-Object {$_.LastWriteTime -lt ((Get-Date).AddDays(-21))}).Count #Считаем папки
                    $FILEINDOCS = Get-ChildItem $DOCSPATH -Recurse -File | Where-Object {$_.LastWriteTime -lt ((Get-Date).AddDays(-21))} #Получаем список всех файлов
                    $FILEINDOCSCOUNT = ($FILEINDOCS | Measure-Object).Count #Их количество
                    $FILEINDOCSSIZE = ($FILEINDOCS | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum /1MB #Размер в Mb
                    $FILEINDOCSSIZE_ROUND = [math]::Round($FILEINDOCSSIZE) #И округляем его до целого (меньше единицы будет отображаться как ноль)
                    #Работаем с рабочим столом
                    $FOLDERSINDESKTOP = (Get-ChildItem $DESKTOPPATH -Recurse -Directory | Where-Object {$_.LastWriteTime -lt ((Get-Date).AddDays(-21))} | Measure-Object).Count #Папки
                    $FILESINDESKTOP = Get-ChildItem $DESKTOPPATH -Recurse -File | Where-Object {$_.LastWriteTime -lt ((Get-Date).AddDays(-21))} #Файлы
                    $FILESINDESKTOPCOUNT = ($FILESINDESKTOP | Measure-Object).Count #Количество файлов
                    $FILESINDESKTOPSIZE = ($FILESINDESKTOP | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum /1MB #Размер файлов
                    $FILESINDESKTOPSIZE_ROUND = [math]::Round($FILESINDESKTOPSIZE) #Округляем
                    #Добавляем строку со всей этой инфой в целевой файл:
                    $COMP.Name + ';' + $PROFUSERNAME + ';' + $FOLDERSINDOCS + ';' + $FILEINDOCSCOUNT + ';' + $FILEINDOCSSIZE_ROUND + ';' + $FOLDERSINDESKTOP + ';' + $FILESINDESKTOPCOUNT + ';' + $FILESINDESKTOPSIZE_ROUND | Out-File $OUTFILE -Append utf8;
                    $COMP.Name.ToString() | Out-File $SuccesFile -Append utf8; #Добавляем имя обработанного компьютера в контрольный файл
                    $M++
                }
            }
        }
        $IsSuccess = $COMP.Name.ToString() -in (Get-Content $SuccesFile) #Цикл закончен, проверяем, попал ли в итоге компьютер в контрольный файл
        #Если нет - заносим его в файл с необработанными компьютерами:
        if ((-not $IsSuccess) -And $NOTPKB) {$COMP.Name + ' - ' + [datetime]::FromFileTime($COMP.lastLogon).ToString('g') | Out-File $DONTSUCCESSFILE -Append utf8}
    }
}
