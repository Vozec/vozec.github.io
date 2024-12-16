bigstr = "Nr0.27465307216702745"

def rev(input_):
  final = ""
  for i in range(len(input_)):
    a = ord(input_[i])
    b = ord(bigstr[i%len(bigstr)])
    final += chr(a - b)
  return final

allstring = [
'«{`zg£}knswiyw¼|¡¢«¨¥¦¨jy×',
'¤Úai«m©nidldìhªdz¢{a°¥¡¦Éz',
'¿§¤}udmµd`wª~±¨¥~xi¡¥ÀÛ',
'¢¸sq}¯ i©db¬£k¨f~à_¥¤¨h§¤°f«¢©g©Âë­',
'Åª°xie|hv£Ùt¨|¤  sf¢bclÃ`',
'»Ý¬ª~¢t¤¡e®­¯Ö{~e¢lc®e¤¤¨ry}lwÈ¸s',
'¶ug¦j~xè¤¨zgx«¦©yz­¼Èe',
'¹¥¨|¨¨¤m§b|j¬¬j£âd_ig}jy«¦¬dj¯w£Ê¡',
'Üf¬§ighiª¸guzd~­|°¥¡ß',
'´ç¢xn§¨~~w«ª¬«Ùwy¢jmr®~avgµ¥£',
'ârg£eh§¤¯zhyh³Äa¦kd §¤do}¡wÈ',
'¶¨~¤px¢|¢gª±`di¬©»¿|fw}h«¡¬`¤æy',
'¤Úai«m©nidldìhªdz¢{a°¥¡¦Éz',
'»Ë¡~t~i§tz§ª~Üx lhfg}uy±Õ',
'Åe¡¤}{q¦m`cmf®¤¨j¦fa®}¬d²ã¤',
'³Å|«¢¯©|y¤£ubnÕg«£m¥fw©¨°¨¡ªh¹Àb',
'«{e©wf{sr¢c«¯à|i¯hwkpwÀÙ',
'µÈffs¦¡edpxØa¯}m{az¨nu®kxÜ',
'¥³aeo{c}¢¦~kz©»Æha¦¢xuyz§|nß',
'¥Ü~~zxk¤§¦|oªeË¡ ¯¢id{Áç'
]

for string in allstring:
  print(rev(string))