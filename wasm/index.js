// for the initial development is hardcoded
const inputs = {
	Private: [3],
	Public: [35]
};
const circuit = {"NVars":8,"NPublic":1,"NSignals":8,"PrivateInputs":["s0"],"PublicInputs":["s1"],"Signals":["one","s1","s0","s2","s3","s4","s5","out"],"Witness":null,"Constraints":[{"Op":"in","V1":"","V2":"","Out":"s1","Literal":"","PrivateInputs":null,"PublicInputs":null},{"Op":"in","V1":"","V2":"","Out":"s0","Literal":"","PrivateInputs":null,"PublicInputs":null},{"Op":"*","V1":"s0","V2":"s0","Out":"s2","Literal":"s2=s0*s0","PrivateInputs":null,"PublicInputs":null},{"Op":"*","V1":"s2","V2":"s0","Out":"s3","Literal":"s3=s2*s0","PrivateInputs":null,"PublicInputs":null},{"Op":"+","V1":"s3","V2":"s0","Out":"s4","Literal":"s4=s3+s0","PrivateInputs":null,"PublicInputs":null},{"Op":"+","V1":"s4","V2":"5","Out":"s5","Literal":"s5=s4+5","PrivateInputs":null,"PublicInputs":null},{"Op":"*","V1":"s5","V2":"1","Out":"s1","Literal":"equals(s1, s5): s1==s5 * 1","PrivateInputs":null,"PublicInputs":null},{"Op":"*","V1":"s1","V2":"1","Out":"s5","Literal":"equals(s1, s5): s5==s1 * 1","PrivateInputs":null,"PublicInputs":null},{"Op":"*","V1":"1","V2":"1","Out":"out","Literal":"out=1*1","PrivateInputs":null,"PublicInputs":null}],"R1CS":{"A":[["0","0","1","0","0","0","0","0"],["0","0","0","1","0","0","0","0"],["0","0","1","0","1","0","0","0"],["5","0","0","0","0","1","0","0"],["0","0","0","0","0","0","1","0"],["0","1","0","0","0","0","0","0"],["1","0","0","0","0","0","0","0"]],"B":[["0","0","1","0","0","0","0","0"],["0","0","1","0","0","0","0","0"],["1","0","0","0","0","0","0","0"],["1","0","0","0","0","0","0","0"],["1","0","0","0","0","0","0","0"],["1","0","0","0","0","0","0","0"],["1","0","0","0","0","0","0","0"]],"C":[["0","0","0","1","0","0","0","0"],["0","0","0","0","1","0","0","0"],["0","0","0","0","0","1","0","0"],["0","0","0","0","0","0","1","0"],["0","1","0","0","0","0","0","0"],["0","0","0","0","0","0","1","0"],["0","0","0","0","0","0","0","1"]]}};
const setup = {"G1T":[["1","2","1"],["8575626224492235243533435898870260119236182852755699776978120368205667538606","2933778004839945360708728461901701604240919170877802540225719058474943204185","14628407423970810052294035912959698878927568860529167454163145630753491346427"],["18454957249961765489874831143286810511802306936296106357052197603472405277808","14658598166757382612557279292328692545566235650603047825701555710007467968709","18743794331641832114797690908608583132817489068876568575418379674338076077152"],["21778929521183110696789571313120683179752980563944219483463209390502538057800","2528698833815927698858200632574058746151199880545906220333922530665914312707","11933651651917555824999286820884803109137989997564081355855419917633674907766"],["5868208941349652345991404474752004628673500171098375079813427360273763635110","4284425519100680585302546062413495108310084471914010039544675362412786357903","20855229450103488850737836984908832945536177391089017094645459600772220658951"],["4366609998121355855474770129521248316882619029481987263339453513161919905653","18298206710554424242507715874337041639276079224224730722942797746591756250445","16051413175194189400019433204401104613509047319378027692377533602189186706802"],["5562634954901756481593494808776353761597049590911471091472523505210262266727","12649655064245384312579564660310524704608549713434941098550348481751678809134","13984478717807435647122191548027513516160161817430214800786892756493218414971"]],"G2T":null,"Pk":{"A":[["3902249879669161685512196293707054296727897468441172006734746540263778553009","1412420343759862572462926710363248860501703957554240820750807290571502311144","2249384855013937606258946183561629730580974664070374232309925751321457797021"],["3672480284051680542894417049925388865827639715367049694712178524178731645964","9098759319134087749764453777394234473406765824846519121657831226777813367370","15847483628798852497403624280680555243278418074552427350491277493620402852072"],["8667940891217799053282198735975652557520306843886415105939223075964668940834","11330984995652525184893899066114448756634522714492323539374533687583277348631","625396587507860914735840906883949854703160873630715906208203334883717878338"],["20235412408226679010836378340147112502013802058967017699689541293967994324512","567103332961643161247245877785375903891230873735627361457299697585244915075","1151849661714113776777051252266554080382698677599845276176540258251530952008"],["18884862772625215814645550891644927806456099652538370545682545649828872986769","1821214577629122285941690503772493383066521187352267386988336689284973402326","14075767416621074498646558215666976946884509768218809290046389590531851678622"],["2064205892869746570295557779630845841334682836848164949125091516144188555394","8362981746921290522960209031534908689070067715253578609695290670282161683817","2247795621323238473214502926269611611188190175931708004849502949263061715912"],["15867800775858987237737660350267641821146505778108412900024793692303698156899","19839735904441315572183873044166316423387844788671113800937964457697715260543","20168617069726248283717765968123357521244926068960351034800445727260608671678"],["0","0","0"]],"B":[[["9483094236534571682182215462961592031579314049158704697972560045449446567638","486112660838316223177748786518939847366271439618152288625040264257357426731"],["12266911373462797403356949289869688674616283163894063621502828046398800398990","3625449786130562055782693578953089136657506988233259053631964025118092862171"],["15249686478347725239938794659776734142747194422653250871845918222489394476896","6467514790149158411685465571133818451456638139868469970886010113397057037535"]],[["0","0"],["0","0"],["0","0"]],[["16753416069771008653712116339962547821414102953385167341248554666274850970245","16118874239370436120147740628680683076832649657752412781619133194763429379033"],["3149380595622531259488908287713230897004518449768011926193160828838373540194","8791376655175439798878441328619596126799692276835763783312434315313685697711"],["4289162649938302409091338730339675062777051314154772713587852602265702296552","7139858067499443509715881857837775267281277306153960899098964485804376451319"]],[["0","0"],["0","0"],["0","0"]],[["0","0"],["0","0"],["0","0"]],[["0","0"],["0","0"],["0","0"]],[["0","0"],["0","0"],["0","0"]],[["0","0"],["0","0"],["0","0"]]],"C":[["0","0","0"],["452504233378077817421968372660828589248698511439695455859043803559863591434","20826818777646605158149830417858056568282979556550187874142948518530696776984","67545357455853110589965963691805962207911030549432877146476426820215669727"],["0","0","0"],["11087299143339322336104611109891901658196905570246178436223058120756029528013","13685807830217349551175376595976929403791341825355825502139500994224288776706","4921018326168436622835711189416351331946749307879728990511118302700312269456"],["19485643034175792178163108308322831106551793166123376188997671532704626016286","8257555791460598147194530503219137838105743159797937344504121423927511009186","18871836212014309199393626697291742966563504245822135643779397484003797436241"],["12921730572562050303554019236265467542655278905712200757270209481282431790316","8208126625363317974792168365775321152784413447574757011891347365799548201213","3775789595468249016693882675250633755953697785196461896396982719703830317045"],["16195765156345604139107669377209950888548585705571396636497096729498949233170","1281604834426446577818956823469728825089410370063844028682015790480247829541","19784447533783054714509015931266797723649053010543929673386763496789005847986"],["13336063360013921202751962386495342381037024526391575259398727659497975016895","2311776974020160443662080559190122011056081857579221775104191259973825887398","14013821065681001708529278505398680203069117693772650572755005836524284565038"]],"Kp":[["10270730247583150317421024803636151412895787234437446685559087014676440855987","12249851880888656578078622206546923979404909447349636059234479487873193580771","10352337369310715938914117514146547576575547826976630346494647467027527590048"],["11066072207629347583054784906182857391171651652156992876241847737075684673673","15130197654433921798452524887549977089966102739803647627184910043787576369109","17404674219138545094322570249013835104062402974316800589564811399933801049566"],["14864877624562224543748795743017769853704420620207337057079481448225975068348","5647231549965996402431809106932126957464132955295625098876436065029216269990","19226714859966000734891539434729678790259773119147462579990179805929312680238"],["915153020049126432079408605236732995388440856037161363071817205571243737235","12380433681885418895798615221021123404215332052624367444540116708118951519091","14809461715434073130054423358195040108349605009027452238217040333853993050609"],["8080317507962347752127857415457811344496627249373431450951670980704479887743","12252496533585894721881099822144217497700079135495782729963394798181595722392","2640494132351364858419969802954450113747991539748690648581958385273028321144"],["179713073641823824219986510731835531938973508646552874675605030471026670558","12134967632609417960726493758555514770951054767097024642948691666219896428666","7566271664452686639594491222671436316074104604486690426607237321070412773699"],["19221875851590621754775366415180467766082972794923104443791021972717461138283","1551882011953603674531753787399615108390177538817489289393790465249027454042","20451622561509076366681138907563405683082731600124850963791374820458886504439"],["2865373458352327862754300705076500112993949566179073375852339656279828872122","3807886606343637681106167390610416073673852686850736266803909387591982945884","15528839551827723412313389353214350066287203905648911871971951458958942598466"]],"Ap":[["8774769459846963005194211989541771650746540578516450980934429155387835676362","18124217260784212186962796832680177754188694608529864771067390565827387179055","2950915544052867175471419779727028472561230950002201308460172720403773626114"],["12608117810102351826723441084042895115880387424526993707317712339687456974831","5421302585671950984291255785653748446611562143106327411629522947432113705424","11414326579769919500149438676554751973208842490344351795247231414313202315490"],["5148800542584889714511009208176880305285940531885462428115121315957465406555","9895304148524924445216012800179791656340897879481578222479988615516837537918","16484695189291856449279886693979507303782401833361607899445671999680389574703"],["14842984023612426331673397297597710887115312262280874155205200392557434733","11566988958660987741585887320406815382349200306071598157833382553761383202895","12724758205891038354068958409121343272805384738610358452282032185672153281922"],["16148986286344558481619138671217758322621206389763204069739438434122138559895","12310242321059446781347322826096220475849384867948961176102995162419647659020","505361307032094078882564155690582364305146243509951875520722283479787292676"],["8535305474940673933865765204818301946104278374977304970658756896006370871951","20748088137647310365446524304013688743735530319573002353360195284726753570803","1762445709757217394983149820371328979604644379316103448091311419947991704185"],["17413587275445021980401455255188250191575142271882622317832940732360687497906","13225040494123533363798870113355021168769729359974069264263265367006225692292","6805174651166353793479430700999955221680577728441130211221603706442048363667"],["0","0","0"]],"Bp":[["1446662920161440386158926658337095442845234501040816434926666938514262098740","18966597146105477920735776744754667981781800492082938910861161145002470984060","6012093054045648561406536241021127307997186153471949390832850083203146646108"],["0","0","0"],["10628384530419813069205954601806945930384066395423071480814760143006452112706","8497870536327557859589108645477201961797670370461730065048426466843396066984","3329957171489780291015578410680526097411251026152446362865497158699197050721"],["0","0","0"],["0","0","0"],["0","0","0"],["0","0","0"],["0","0","0"]],"Cp":[["0","0","0"],["14920937290018562140937570572571014056740753097581661083979403204920891658742","21811944937123197403496283148929198873872814082189005486385636700926879750209","14030127762547581758363998031388878597541430681512379343404666475535743344213"],["0","0","0"],["14379022274305279958710903963796316757770071705869530789581703036458746794769","8176961606726118499175853632676212724311900262565784774028821367476981532535","18879248469583037953966988520679747897380998353147295504451659232634221564201"],["6584394006531031864174152183024256880195715748537433666438135393819019975805","16854040579713775108259443344736799730509709441800073406825213745815991711957","13036416345582014951910903015636059420209703549614657491825167945925831684745"],["8261450318962865312319211141023670887023587939978621014889639986777028730759","13638915109503325597390872023164493151164961051469741054244917796222754105456","11536475689379687031152013881207096151854000458510681147360024206311605875869"],["14363802979506866314489413398127831635994328164726272702554010888130325735353","5390561501337839036731461825395126872871195524442771420517483943593676920855","8260230864537213129923324620217992505641853737814833592113891317968785398695"],["21099758545013781800989242554510167577611563271614464838950229743685435084911","8124530770006885515246883500407472402497205176823674986451771394572328608635","67223368706533218675640727387047699211751832696016695819563918855507975507"]],"Z":["720","21888242871839275222246405745257275088548364400416034343698204186575808493853","1624","21888242871839275222246405745257275088548364400416034343698204186575808494882","175","21888242871839275222246405745257275088548364400416034343698204186575808495596","1"]},"Vk":{"Vka":[["",""],["",""],["",""]],"Vkb":["","",""],"Vkc":[["",""],["",""],["",""]],"IC":null,"G1Kbg":["","",""],"G2Kbg":[["",""],["",""],["",""]],"G2Kg":[["",""],["",""],["",""]],"Vkz":[["",""],["",""],["",""]]}};
const px = ["21888242871839275222246405745257275088548364400416034343698204186575808491809","10214513340191661770381656014453395041322570053527482693725828620402043982207","6250309353402993035685918085034577441952144056563245362589376084388869725846","8684363028317712437715356353558094792076827912572472885439518975877531461332","4676585224700845145864220486776033543224569523514814745192926496344784986728","15086167396042000456999692848727670503739063657925634782028102538317006907054","21632626702190133686375495752236851586646219728193583201883487889998783136513","12304536531079092564172545451934558461236042348706097084183122422939664568112","5627862446735063646553285921653823681621549943926414385940458402833120205122","19793152958064844596228144454594339151253283687552138463809498762698702751890","12878849570320523547145145010088473306441356493332753911233629701770305283468","21470238233661789063488227857761042404565669941380311465606745426068284375041","14598495318168266605115151979982065705759253455717291424254733984391562089814"];
function callGenerateProof() {
	console.log("s", JSON.stringify(setup))
	let r = generateProofs(
		JSON.stringify(circuit),
		JSON.stringify(setup),
		JSON.stringify(px),
		JSON.stringify(inputs),
	);
	console.log("r", r);
	document.getElementById("proofResult").value = r;
}