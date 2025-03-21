from nanoid import generate

ZALGO_CHARS = "ḁ̵̏b̶̜̚c̸͉̓d̸͍͆ê̷̗f̶͕̔g̴̥͐h̵̙̅i̶͓̐j̴͇͂k̷̟͗ĺ̵̨m̶̧͋n̸̚ͅo̷͚̕p̸͉͋q̴̑ͅr̷̫͑s̷̺̃ẗ̴͓́ǔ̸͚v̶̩͐ẅ̵̼́x̴̝̊y̶͍͛ż̷ͅ1̵̖̉2̴̟̿3̸̫̏4̶̤̒5̶͓̎6̵͖͘7̴͖̍8̴̠͗9̸̯̊0̸̫̿!̷̱̏@̸̢̈́#̴͙̾$̷̲̕%̷͍̄^̶̰̾&̶͈́*̸̨̚(̶͙͠)̴̢̚_̴̪͒+̷̱̕"


def zalgo_id(length=16):
    return generate(ZALGO_CHARS, length)
