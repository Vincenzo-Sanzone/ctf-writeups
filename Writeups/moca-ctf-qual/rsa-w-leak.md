## ## Introduction
The challenge provides us with 3 elements:
- **N**: RSA module;
- **CT**: the encrypted flag;
- **Leak**: Data that gives us information to decrypt the flag.

## Solution analysis
Leak is a rational number obtained by the sum of two fractions:

``` python
mpf(secrets.randbelow(n)) / mpf(phi) + mpf(secrets.randbelow(n)) / mpf(n
```
Since it is a rational number, we can write it as a finite continued fraction. Knowing that *phi* is smaller than *n*, we know that:
``` python
mpf(secrets.randbelow(n)) / mpf(phi)
```
will have greater weight in the sum of the two fractions, and so the continuous fraction convergent can be a good approximation of phi. So we derive the original leak (approximation) from there, we derive the continuous fraction convergents, which are an approximation of phi. We use the phi approximation to decrypt the flag, verifying that it starts and ends with the known pattern.

## Script
``` python
from Crypto.Util.number import long_to_bytes
from sympy import Rational
from sympy.ntheory.continued_fraction import continued_fraction_convergents, continued_fraction
from mpmath import mp, mpf

mp.dps = 1024

n = 27996746662200792953757045219629741419023460330773808104305746698717616456477378691366287747656230128603585574987779523696593020813803362953722663980126677262042344173160523724295893104987901282918922898573605453333040442281449491112779042781307789622911019485509654426810659352539331376595886121398942748136305672878300615297072344281084598966684918272732374276085166486972221692242713556629469437409168092726209166105059929636322826607220431880874794446337596297955163560832034350361135234304517051773136564377888611046690516961094585175515308288452925926298522943160512694695287433088528728904567568874643298269701
ct = 21052168501124016207528162518318174555933213897865998665158008308872790259327772514180397564628093354009392752165625445080134143682891206000132586241016490141275928997440986115996139806788437977644866174181411921237256277985846925759596596799716189653107639208494163095591904048441743084747851838033044978392871412893396315558854902485047498916693929676947386328285503027430796011448683836224568769772746035607807111369514135505880392859165843581889787900469940409135426615110939030394694758595586694060912471752863169076557802320711864649223264656439041462907943217796932186865504007171888883836211251626205009503088
leak = 803540384816316597746987025428306044028537535582398446088658227974079344752658925399803131911460635645718918891005841548168564250569450315091004679853963666277624676320741164988579534946997311051644125179644662661206565440010929886107231980491175680124652942731885148405930323057302282765395824895476770440745293594406908041968221804818892357019047131211936522106195853097190784941568974825020595703089809122837776139603790482936615139054468022086823044805998564933557092661058870155402900731464228108933624236172124124346843417170268535266430623283388168278343827291615736877359185455447942394007345850634050834492792456652530107234773404891614035464311941908975370863981452088242984541995836610571434443257261355474058810937067940274116197870976926644739739329157624834429888298409305285790049363071370134347352300399106045458099618832903096927278313664222571885457382701966938168058863380259034993463635661014736870460851696320184294015447514524325654488478580292039746925564943789824014487784013328301912693133525760477806890447806175213278087820030822421559228291988560297320361772013943601095463623298797564423462107584674632770633358717050966616598466317386969412947682252941540173163457728463675524898463752915253729955400420519325827816123183411534810102098968199955663129704073779897462072072086802269709464081457906598304973576852070681606517837149584220746754367904633115044818315675650030001783111364661651103686360152443311605379025720798043448070948561452746128893587037667944103170079946490451643457292658951073396464651450350276587568392924281398289396567063358837466421958180221455482442389564910576146926437282300263436383990128128675868997443404811327285451511057242913278160235959804493706220225916480639423226841998993755738183407532243775688334837491375681065898391653853891561732745447578474063344091717211966739825442331820493628466336076133445020139953175221715701786694296620274033799219409125067367535200079843992173997203135483768917267359556259667002094940704268596200703664038612038989717495532362611635498100685548990674197007377488010695636956620136602728137150249520190705817155474825361703617363312368938016672406746000274565650583072590673819963441741406035553302719768637032657831433777914132550585193715895634115488995987987242611237304063002343729027215339163340474848551592103724225656741560903192959538022281979142365514245778938340257912111170980687071264293743436438816880881349656182113657128348093565408475360395220766192

scaled_leak = leak / mpf(2**8192)

frac_approx = Rational(str(scaled_leak))
cf = continued_fraction(frac_approx)
convergents = list(continued_fraction_convergents(cf))

known_prefix = b'PWNX{'
known_suffix = b'}'

for conv in convergents:
    phi_approx = conv.denominator

    try:
        d = pow(65537, -1, phi_approx)
    except ValueError:
        continue

    try:
        flag_int = pow(ct, d, n)
        flag_bytes = long_to_bytes(flag_int)

        if flag_bytes.startswith(known_prefix) and flag_bytes.endswith(known_suffix):
            print("Flag found:", flag_bytes.decode())
            break
    except Exception:
        continue
else:
    print("No flag found.")
```