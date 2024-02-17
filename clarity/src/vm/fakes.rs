#![allow(non_snake_case)]

use fake::{locales::EN, Dummy};
use rand::Rng;
use stacks_common::{types::{chainstate::StacksAddress, Address}, util::hash::Hash160};

use self::raw::*;

pub mod raw {
    use std::{collections::BTreeMap, sync::atomic::AtomicU32};

    use fake::{locales::EN, Dummy, Fake, Faker};
    use rand::Rng;

    use crate::vm::{
        representations::Span, types::{
            signatures::{CallableSubtype, FunctionArgSignature}, ASCIIData, BuffData, BufferLength, CharType, FixedFunction, FunctionArg, FunctionSignature, FunctionType, ListData, ListTypeData, OptionalData, ResponseData, SequenceData, SequenceSubtype, StandardPrincipalData, StringSubtype, StringUTF8Length, TraitIdentifier, TupleData, TupleTypeSignature, TypeSignature, UTF8Data
        }, ClarityName, ContractName, SymbolicExpression, SymbolicExpressionType, Value
    };

    use super::ENGLISH_WORDS;

    const MAX_RECURSION_LEVEL: u32 = 1;

    impl Dummy<Faker> for StandardPrincipalData {
        fn dummy_with_rng<R: Rng + ?Sized>(config: &Faker, rng: &mut R) -> Self {
            StandardPrincipalData(1, rng.gen())
        }
    }

    pub struct EnglishWord<L>(pub L);
    impl Dummy<EnglishWord<EN>> for &'static str {
        fn dummy_with_rng<R: Rng + ?Sized>(config: &EnglishWord<EN>, rng: &mut R) -> Self {
            ENGLISH_WORDS[rng.gen_range(0..ENGLISH_WORDS.len() - 1)]
        }
    }

    impl Dummy<EnglishWord<EN>> for String {
        fn dummy_with_rng<R: Rng + ?Sized>(config: &EnglishWord<EN>, rng: &mut R) -> Self {
            ENGLISH_WORDS[rng.gen_range(0..ENGLISH_WORDS.len() - 1)].into()
        }
    }

    impl Dummy<Faker> for ClarityName {
        fn dummy_with_rng<R: Rng + ?Sized>(config: &Faker, rng: &mut R) -> Self {
            ClarityName::from(ENGLISH_WORDS[rng.gen_range(0..ENGLISH_WORDS.len() - 1)])
        }
    }

    impl Dummy<Faker> for ContractName {
        fn dummy_with_rng<R: Rng + ?Sized>(config: &Faker, rng: &mut R) -> Self {
            ContractName::from(ENGLISH_WORDS[rng.gen_range(0..ENGLISH_WORDS.len() - 1)])
        }
    }

    impl Dummy<Faker> for UTF8Data {
        fn dummy_with_rng<R: Rng + ?Sized>(config: &Faker, rng: &mut R) -> Self {
            let val = Value::string_utf8_from_string_utf8_literal(ENGLISH_WORDS[rng.gen_range(0..ENGLISH_WORDS.len() - 1)].to_string())
                .expect("failed to fake utf8 string literal");
            
            if let Value::Sequence(SequenceData::String(CharType::UTF8(utf8_data))) = val {
                utf8_data
            } else {
                panic!("failed to fake utf8 string literal")
            }
        }
    }

    impl Dummy<Faker> for ASCIIData {
        fn dummy_with_rng<R: Rng + ?Sized>(config: &Faker, rng: &mut R) -> Self {
            ASCIIData {
                data: ENGLISH_WORDS[rng.gen_range(0..ENGLISH_WORDS.len() - 1)].as_bytes().to_vec()
            }
        }
    }

    impl Dummy<Faker> for TypeSignature {
        fn dummy_with_rng<R: Rng + ?Sized>(config: &Faker, rng: &mut R) -> Self {
            random_type_signature(None, rng)
        }
    }

    fn random_type_signature<R: Rng + ?Sized>(level: Option<u32>, rng: &mut R) -> TypeSignature {
        let next_level = Some(level.unwrap_or_default() + 1);

        let mut signatures = vec![
            TypeSignature::SequenceType(SequenceSubtype::StringType(
                StringSubtype::ASCII(BufferLength(rng.gen_range(5..50))))),
            TypeSignature::SequenceType(SequenceSubtype::StringType(
                StringSubtype::UTF8(StringUTF8Length(rng.gen_range(5..50))))),
            TypeSignature::PrincipalType,
            TypeSignature::BoolType,
            TypeSignature::IntType,
            TypeSignature::UIntType,
            TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength(rng.gen_range(50..100)))),
            TypeSignature::CallableType(CallableSubtype::Principal(Faker.fake())),
            TypeSignature::TraitReferenceType(TraitIdentifier {
                name: Faker.fake(),
                contract_identifier: Faker.fake()
            }),
            TypeSignature::ListUnionType(
                (0..rng.gen_range(1..3))
                    .into_iter()
                    .map(|_| Faker.fake())
                    .collect()
            ),
        ];

        if let Some(level) = level {
            if level < MAX_RECURSION_LEVEL {
                let mut recursive_signatures = vec![
                    TypeSignature::SequenceType(SequenceSubtype::ListType(
                        ListTypeData { 
                            max_len: rng.gen_range(1..5), 
                            entry_type: Box::new(random_type_signature(next_level, rng))
                        })),
                    TypeSignature::OptionalType(Box::new(random_type_signature(next_level, rng))),
                    TypeSignature::ResponseType(Box::new(
                        (random_type_signature(next_level, rng), random_type_signature(next_level, rng))
                    )),
                    TypeSignature::TupleType(TupleTypeSignature {
                        type_map: (0..rng.gen_range(1..3))
                            .map(|_| (Faker.fake(), random_type_signature(next_level, rng)))
                            .collect()
                    }),
                ];

                signatures.append(&mut recursive_signatures);
            }
        }

        signatures[rng.gen_range(0..signatures.len())].clone()
    }

    impl Dummy<Faker> for SymbolicExpressionType {
        fn dummy_with_rng<R: Rng + ?Sized>(config: &Faker, rng: &mut R) -> Self {
            random_symbolic_expression_type(None, rng)
        }
    }

    fn random_symbolic_expression_type<R: Rng + ?Sized>(level: Option<u32>, rng: &mut R) -> SymbolicExpressionType {
        let next_level = Some(level.unwrap_or_default() + 1);

        let mut types = vec![
            SymbolicExpressionType::Atom(Faker.fake()),
            SymbolicExpressionType::LiteralValue(random_value(next_level, rng)),
            
        ];

        if let Some(level) = level {
            if level < MAX_RECURSION_LEVEL {
                let mut recursive_types = vec![
                    SymbolicExpressionType::List(
                        (1..rng.gen_range(1..3))
                            .into_iter()
                            .map(|_| Faker.fake())
                            .collect()
                    ),
                ];

                types.append(&mut recursive_types);
            }
        }

        types[rng.gen_range(0..types.len())].clone()
    }

    impl Dummy<Faker> for Value {
        fn dummy_with_rng<R: Rng + ?Sized>(config: &Faker, rng: &mut R) -> Self {
            random_value(None, rng)
        }
    }

    fn random_value<R: Rng + ?Sized>(level: Option<u32>, rng: &mut R) -> Value {
        let next_level = Some(level.unwrap_or_default() + 1);

        let mut values = vec![
            Value::Bool(Faker.fake()),
            Value::Int(Faker.fake()),
            Value::UInt(Faker.fake()),
            Value::Principal(Faker.fake()),
            Value::CallableContract(Faker.fake()),
        ];

        if let Some(lvl) = level {
            if lvl < MAX_RECURSION_LEVEL {
                let mut recursive_vals = vec![
                    Value::Tuple(TupleData { 
                        data_map: (0..rng.gen_range(1..3))
                            .into_iter()
                            .map(|_| (Faker.fake(), random_value(next_level, rng)))
                            .collect(),
                        type_signature: TupleTypeSignature {
                            type_map: (0..rng.gen_range(1..3))
                                .map(|_| (Faker.fake(), random_type_signature(next_level, rng)))
                                .collect()
                        }
                    }),
                    Value::Optional(OptionalData {
                        data: if level.is_none() { Some(Box::new(random_value(next_level, rng))) } else { None },
                    }),
                    Value::Response(ResponseData { 
                        committed: Faker.fake(),
                        data: Box::new(random_value(next_level, rng))
                    }),
                    Value::string_utf8_from_string_utf8_literal(ENGLISH_WORDS[rng.gen_range(0..ENGLISH_WORDS.len() - 1)].to_string())
                        .expect("failed to fake utf8 string literal"),
                    Value::string_ascii_from_bytes(ENGLISH_WORDS[rng.gen_range(0..ENGLISH_WORDS.len() - 1)].as_bytes().to_vec())
                        .expect("failed to fake ascii string literal"),
                    Value::Sequence(SequenceData::List(ListData {
                        data: (0..rng.gen_range(1..3))
                            .into_iter()
                            .map(|_| random_value(next_level, rng))
                            .collect(),
                        type_signature: ListTypeData { 
                            max_len: rng.gen_range(1..3), 
                            entry_type: Box::new(random_type_signature(next_level, rng)) 
                        }
                    })),
                    Value::Sequence(SequenceData::Buffer(BuffData { 
                        data: (10..rng.gen_range(20..40))
                            .into_iter()
                            .map(|_| rng.gen())
                            .collect(),
                    })),
                ];

                values.append(&mut recursive_vals);
            }
        }

        values[rng.gen_range(0..values.len())].clone()
    }

    impl Dummy<Faker> for FunctionSignature {
        fn dummy_with_rng<R: Rng + ?Sized>(config: &Faker, rng: &mut R) -> Self {
            FunctionSignature {
                args: (0..rng.gen_range(1..3))
                    .into_iter()
                    .map(|_| (random_type_signature(None, rng)))
                    .collect(),
                returns: random_type_signature(None, rng)
            }
        }
    }

    impl Dummy<Faker> for FixedFunction {
        fn dummy_with_rng<R: Rng + ?Sized>(config: &Faker, rng: &mut R) -> Self {
            FixedFunction {
                args: (0..rng.gen_range(1..3))
                    .into_iter()
                    .map(|_| Faker.fake())
                    .collect(),
                returns: random_type_signature(None, rng)
            }
        }
    }

    impl Dummy<Faker> for FunctionArg {
        fn dummy_with_rng<R: Rng + ?Sized>(config: &Faker, rng: &mut R) -> Self {
            FunctionArg {
                name: Faker.fake(),
                signature: random_type_signature(None, rng)
            }
        }
    }

    impl Dummy<Faker> for FunctionArgSignature {
        fn dummy_with_rng<R: Rng + ?Sized>(config: &Faker, rng: &mut R) -> Self {
            let sigs = vec![
                FunctionArgSignature::Union(
                    (0..rng.gen_range(1..2))
                        .into_iter()
                        .map(|_| random_type_signature(None, rng))
                        .collect()
                ),
                FunctionArgSignature::Single(random_type_signature(None, rng))
            ];

            sigs[rng.gen_range(0..sigs.len())].clone()
        }
    }

    impl Dummy<Faker> for FunctionType {
        fn dummy_with_rng<R: Rng + ?Sized>(config: &Faker, rng: &mut R) -> Self {
            let fn_types = vec![
                FunctionType::Fixed(Faker.fake()),
                FunctionType::Variadic(Faker.fake(), Faker.fake()),
                FunctionType::UnionArgs(
                    (0..rng.gen_range(1..2))
                        .into_iter()
                        .map(|_| random_type_signature(None, rng))
                        .collect()
                    , random_type_signature(None, rng)
                ),
                FunctionType::ArithmeticBinary,
                FunctionType::ArithmeticUnary,
                FunctionType::ArithmeticComparison,
                FunctionType::ArithmeticVariadic,
                FunctionType::Binary(Faker.fake(), Faker.fake(), Faker.fake())
            ];

            fn_types[rng.gen_range(0..fn_types.len())].clone()
        }
    }

    impl Dummy<Faker> for SymbolicExpression {
        fn dummy_with_rng<R: Rng + ?Sized>(config: &Faker, rng: &mut R) -> Self {
            SymbolicExpression {
                expr: random_symbolic_expression_type(None, rng),
                id: rng.gen(),
                #[cfg(feature = "developer-mode")]
                end_line_comment: None,
                #[cfg(feature = "developer-mode")]
                span: Span::zero(),
                #[cfg(feature = "developer-mode")]
                post_comments: Default::default(),
                #[cfg(feature = "developer-mode")]
                pre_comments: Default::default()
            }
        }
    
    }

}

const ENGLISH_WORDS: &'static [&'static str] = &["glancing", "gwaith", "defines", "panel", "manitowoc", "uspto", "iseries", "cations", "create", "harms", "columbian", "moonlight", "fansite", "pomegranate", "lynnwood", "finalist", "survivor", "veggie", "haymarket", "certainly", "lubricant", "guarded", "challenges", "pelican", "heidegger", "puccini", "louisa", "newsday", "subjects", "dances", "mutex", "apathy", "rhodium", "tumbled", "takers", "incline", "screenshots", "gangbangs", "curled", "orchestral", "nerve", "maude", "cassettes", "sonne", "cried", "shops", "plantar", "confirming", "intestinal", "nosed", "waistband", "prosecutor", "newborns", "cupcakes", "crisis", "travail", "heaton", "edgewood", "diazepam", "yahoogroups", "implicit", "endpoints", "unequivocally", "abilene", "idiom", "larynx", "caloric", "datagrams", "alphabets", "belcher", "alright", "assist", "petitioned", "mortimer", "ruled", "congruent", "thankful", "goulburn", "reset", "cornell", "launchers", "sovereignty", "landers", "mediums", "limitation", "appreciates", "workstation", "preparations", "decimation", "relocate", "remembrance", "discoverer", "overriding", "person", "dudes", "authenticate", "researchers", "native", "northerly", "tablatures", "thanh", "kiowa", "kaplan", "cooke", "buckles", "schoolgirls", "capitalizing", "brdrnone", "artest", "motorized", "daniela", "scrolling", "squaretrade", "fahrenheit", "putters", "runoff", "taranaki", "lexical", "beginners", "emeritus", "artistry", "fulfills", "taxable", "weakens", "choline", "workplace", "sumitomo", "glues", "spake", "camshaft", "satellite", "tougher", "tahitian", "withdraws", "mistaken", "glutamine", "midst", "adelaide", "demeter", "slightly", "discusses", "theatrical", "routine", "scare", "awareness", "counselors", "vented", "covered", "shale", "downstairs", "commodores", "dimensionname", "brothel", "declination", "things", "randy", "suggesting", "burdens", "spartan", "padre", "adirondack", "zacks", "alvarez", "neutrino", "hessen", "decimals", "crafts", "rocklin", "suture", "stakeholders", "finalizing", "fireworks", "constructed", "perfumed", "sparked", "anydvd", "originality", "interrupted", "certs", "multipliers", "visualization", "newlines", "accueil", "moment", "leagues", "capitalists", "staffordshire", "appellees", "witches", "alpaca", "ahora", "altitudes", "stinger", "avanti", "catfish", "shakur", "trying", "suburbia", "maximilian", "optometrists", "overtime", "domicile", "spouses", "hoyer", "gracefully", "searched", "croupier", "obscured", "newsroom", "streams", "torrie", "unproven", "significantly", "downloaden", "heifer", "bumble", "wizard", "deerfield", "abysmal", "shenyang", "bunch", "resale", "delegation", "indepth", "powerseller", "doped", "davids", "wilkins", "blockbuster", "postponed", "pueblo", "pence", "blight", "bastille", "demanding", "lifedrive", "dilated", "spheres", "decreased", "kagan", "savor", "sticky", "homeschooling", "teachings", "sudanese", "tapestry", "statutory", "parkersburg", "declaration", "concatenation", "tacacs", "incomparable", "emigrants", "ullman", "playa", "cardiopulmonary", "slows", "washes", "rayburn", "sagan", "webbing", "glass", "kathy", "screenings", "stamina", "dramas", "jordans", "fixings", "alongside", "apnea", "choreography", "counters", "loire", "silvio", "lighters", "disadvantage", "kentucky", "levine", "hodge", "eigen", "buffets", "bookseller", "shiki", "disqualify", "distinctions", "wheelers", "dominique", "etoile", "inside", "bookshelf", "cranial", "cessation", "hydrographic", "doctrinal", "tankers", "pickett", "obliged", "united", "papua", "darnell", "dominica", "apotheon", "johnstown", "forzieri", "martens", "armoured", "mckean", "centrifugal", "avalanche", "customs", "gilmour", "pharm", "trajectory", "lipoprotein", "fomit", "flush", "dissatisfaction", "facial", "glitches", "bookshot", "patten", "behaviors", "adjacency", "quadrangle", "autoconf", "countenance", "sperm", "jetblue", "craven", "genera", "uclibc", "optional", "maritime", "biloxi", "gareth", "camberley", "aerodynamics", "tomlin", "compton", "replicating", "unlicensed", "mongolia", "shelter", "trois", "executable", "danes", "unlimited", "nogroup", "specificity", "mercedes", "oswald", "larnaca", "middleton", "chatboard", "uncovered", "regal", "costing", "compasses", "chart", "separated", "aligning", "raster", "concurrently", "francesca", "fittings", "coopers", "potters", "technologist", "washington", "leiter", "perfected", "burying", "strict", "therefrom", "freezer", "souvenirs", "interdependent", "herrick", "palais", "brianna", "juneau", "edina", "folate", "remus", "manilow", "abdul", "accepts", "payday", "pussycat", "relativism", "mandatory", "cashing", "kinder", "pornos", "stops", "material", "bigalow", "plainly", "perpetuate", "flammability", "astor", "cairns", "romance", "mathias", "distro", "mackinac", "meeks", "multilayer", "reproduction", "broom", "retailers", "dunlop", "blower", "mooring", "rhoda", "phyto", "bechtel", "medalist", "stipulate", "restriction", "leominster", "regulating", "assortment", "complicity", "holding", "equinox", "instructors", "boland", "ciprofloxacin", "desoto", "sucker", "managment", "guiana", "starfleet", "shout", "disclosed", "leningrad", "useable", "enotes", "carpool", "cherries", "venous", "hannah", "suicides", "toolkit", "earnings", "herder", "halting", "mehmet", "shallow", "astonishing", "mollie", "decoration", "slowly", "ioffer", "messageboards", "breaks", "snipe", "agencies", "danger", "boiler", "jewelry", "multiplexing", "bianco", "threatened", "inhabitants", "planar", "brownfield", "epinephrine", "chopard", "modifiers", "pseudomonas", "crafting", "endpoint", "rhododendron", "phosphorylation", "declared", "artist", "breathless", "measures", "limitations", "grassley", "cerritos", "americana", "premierguide", "peruvian", "marla", "creatively", "letzte", "tabasco", "reykjavik", "centrist", "liste", "deuteronomy", "babydoll", "angie", "commodity", "morten", "circulars", "emperor", "meridian", "gecko", "parti", "revamp", "convene", "share", "decree", "littered", "varieties", "culvert", "carta", "contention", "diffuser", "philosophies", "socialism", "morrell", "institutional", "administrations", "seize", "macleod", "irradiated", "turnovr", "federations", "affaires", "diameters", "sensuous", "madness", "philanthropy", "substr", "cerruti", "amstrad", "gulfstream", "transposition", "parlour", "fleet", "sounded", "beech", "anglesey", "regulators", "intellectually", "reiterated", "stirling", "knockout", "allow", "implantation", "tingling", "abstain", "soundboard", "mcalester", "disassembly", "catered", "officejet", "agreed", "grievous", "slated", "octane", "adventurers", "thirteenth", "molto", "peacekeepers", "provocative", "tournament", "caching", "reasonableness", "aneurysm", "groundwork", "salvatore", "narayan", "conventionally", "itasca", "techie", "roscommon", "jossey", "interlude", "kravitz", "goings", "parenting", "founding", "vegetation", "showers", "cities", "chewable", "condi", "lookups", "flashes", "zydeco", "pandas", "ministers", "beasty", "inventors", "londonderry", "driver", "freshest", "jscript", "lends", "cowboys", "stopping", "doanh", "militia", "frankly", "sensei", "these", "gandalf", "meditation", "spell", "quasar", "lugano", "selectively", "garnish", "impartial", "gilberto", "collie", "subcommittee", "milestone", "originators", "swimwear", "clint", "dieser", "profess", "transsexual", "myspace", "gwendolyn", "oppose", "cypher", "commit", "flood", "baroque", "augustin", "quicksearch", "transylvania", "roots", "happen", "informationhide", "frazier", "foreseen", "recycle", "electrics", "unrelated", "knicks", "sedation", "italians", "thrive", "rectory", "dungeon", "racquet", "paraiso", "alumnus", "shorts", "softening", "uplink", "theorists", "cubes", "ecampus", "arrives", "adipose", "ultralight", "barricades", "transparencies", "cites", "landings", "broderick", "fifths", "racking", "graduate", "gauteng", "tained", "crosby", "coated", "nance", "furman", "careerbuilder", "magnetics", "bleeds", "quickest", "peptidase", "woody", "amara", "windscreen", "greyhounds", "mastering", "clauses", "atrios", "neurology", "proton", "conseil", "katja", "offbeat", "antagonists", "unfpa", "conduction", "nieuw", "slept", "inositol", "cheeses", "akita", "beverly", "behaving", "reserved", "developmentally", "curiosities", "bayes", "moorings", "osgood", "azres", "veranda", "mhonarc", "festival", "cartwright", "filigree", "helical", "fluids", "dorchester", "carbine", "shortly", "thrusting", "villeneuve", "willem", "guardia", "cortisol", "defibrillators", "malta", "marigold", "twofold", "assigned", "feeble", "gateshead", "harcore", "determinations", "approximations", "kites", "rollins", "mpltext", "militaria", "circulation", "diabetics", "coexistence", "dominguez", "ellyn", "subcellular", "villages", "cautious", "diagnosing", "reassurance", "diligence", "tokyo", "apacer", "scratch", "tooled", "catagory", "sumptuous", "covalent", "surgery", "magazin", "enjoying", "criminal", "preowned", "cornwall", "conversions", "attire", "masterbation", "johnston", "amarillo", "lifehouse", "applescript", "coldwell", "mating", "plate", "idyllic", "cobalt", "appear", "knitting", "alluvial", "trainees", "membrane", "famous", "overtly", "rumble", "multiplying", "amour", "mixtures", "rubies", "mascot", "waits", "calypso", "dissociation", "acknowledges", "calabasas", "selangor", "staggering", "horton", "sevilla", "zyxel", "rebounding", "dremel", "ruling", "restricts", "salon", "ruined", "supermodels", "evaluates", "reforming", "worden", "undesirable", "artista", "englishman", "transdermal", "sally", "doris", "baits", "reinforce", "internets", "readings", "neutrons", "donde", "convened", "brodie", "mohan", "nailing", "normally", "aristocrats", "father", "longwood", "dreamweaver", "bowels", "quando", "solves", "expenses", "appealing", "knowit", "jeeves", "provided", "spanking", "caldera", "kronos", "hookers", "rulemaking", "tuscan", "psychiatric", "retails", "horny", "announcer", "calvary", "skaters", "pimpin", "cairn", "wayne", "shave", "genealogy", "titusville", "equator", "unicorn", "pickabook", "reservations", "bottomed", "meilleurs", "intraday", "hemoglobin", "construed", "intrusion", "internat", "mcmullen", "epcot", "iraqi", "patrolling", "murad", "geographic", "ecnext", "toughness", "steiner", "musicals", "micronesia", "grantham", "physicists", "gratuit", "inhabit", "carter", "shimizu", "forcefully", "batters", "mcelroy", "prefered", "crickets", "hatfield", "buisness", "deputy", "disclosure", "emulators", "undertook", "myths", "grisham", "lovely", "postcards", "blackfoot", "knoll", "gritty", "suppressing", "willard", "slipping", "morrisville", "cynical", "constitution", "avenida", "sociale", "liguria", "horrendous", "behav", "storefront", "brought", "irritability", "neuroblastoma", "torrent", "bedlam", "titled", "topic", "automakers", "behemoth", "popping", "cobbler", "warhead", "emissions", "handwritten", "dividers", "pooled", "virginian", "stays", "psycho", "carlos", "mailroom", "confirmed", "buckley", "materialized", "varadero", "mnogosearch", "granada", "ambiente", "mississauga", "grundy", "unverified", "exercises", "lasagna", "truckee", "puppies", "truce", "cluster", "kirkwood", "bigpond", "entail", "scribes", "minerals", "vidio", "tostring", "tariq", "vivian", "foolishness", "osborne", "steamy", "stonehenge", "breathe", "loosening", "euchre", "krazy", "cyclades", "stains", "proponent", "sterility", "carmine", "wisely", "locations", "migratory", "hemisphere", "foraging", "tomaso", "cured", "playmobil", "mania", "treks", "distinct", "carded", "ativan", "darden", "stunt", "mingle", "datasheet", "kleine", "hynes", "biofuels", "confiscated", "blasted", "mater", "jayhawks", "wanadoo", "portions", "holmes", "fatty", "cello", "trafic", "warfare", "slugger", "exiting", "ascend"];