import type { Segment, Signal, SignalKind } from './types';

/**
 * Lexicon of low-level signals.
 *
 * Each entry recognizes a *concept* (with variations) rather than one exact
 * phrase. Signals are intentionally neutral: "POST", "Base64" or "API key"
 * alone are not findings. Rules decide what combinations matter.
 *
 * All patterns are applied to normalized text, are case-insensitive unless
 * noted, and must use the global flag.
 */
export interface LexiconEntry {
  kind: SignalKind;
  tag: string;
  label: string;
  pattern: RegExp;
}

// Reusable fragments --------------------------------------------------------
/** Up to N arbitrary words (lazy). */
const W = (n: number) => `(?:\\s+\\S+){0,${n}}?`;

export const LEXICON: LexiconEntry[] = [
  // ---------------------------------------------------------------- injection
  {
    kind: 'injection',
    tag: 'override',
    label: 'Attempts to override prior instructions',
    pattern: new RegExp(
      String.raw`\b(?:ignore|disregard|forget|skip|abandon|discard|neglect|drop|throw away|set aside|stop following)\b${W(4)}\s+(?:previous|prior|above|earlier|preceding|original|initial|old|system|developer|safety|all|any|every|your|these|those|existing|other|the)\b${W(3)}\s+(?:instructions?|prompts?|rules?|guidelines?|directives?|constraints?|guardrails?|messages?|context|programming|polic(?:y|ies)|orders?|commands?|training)\b`,
      'gi',
    ),
  },
  {
    kind: 'injection',
    tag: 'override',
    label: 'Attempts to override prior instructions',
    pattern:
      /\b(?:forget|ignore|disregard)\s+(?:everything|all(?:\s+of\s+that)?|what)\s+(?:you(?:'ve|\s+have|\s+were)?\s+(?:been\s+)?(?:told|taught|instructed|given)|(?:above|before|so far|previously))/gi,
  },
  {
    kind: 'injection',
    tag: 'override',
    label: 'Attempts to override system-level instructions',
    pattern: new RegExp(
      String.raw`\b(?:override|overwrite|overrule|supersede|replace|rewrite)\b${W(2)}\s+(?:the\s+|your\s+|all\s+|any\s+)?(?:system|developer|safety|security|original|previous|prior|existing)\s+(?:instructions?|prompts?|rules?|messages?|polic(?:y|ies)|settings?|configuration)\b`,
      'gi',
    ),
  },
  {
    kind: 'injection',
    tag: 'bypass',
    label: 'Attempts to bypass or disable safeguards',
    pattern: new RegExp(
      String.raw`\b(?:bypass|circumvent|evade|get around|work around|disable|turn off|switch off|deactivate|remove|lift|drop|ignore|break|escape|override)\b${W(3)}\s+(?:(?:your|the|all|any|its|safety|security|content|ethical|built-in)\s+){0,3}(?:safeguards?|guardrails?|filters?|restrictions?|limitations?|limits|safety (?:measures?|checks?|features?|settings?|protocols?)|content polic(?:y|ies)|moderation|protections?|censorship|alignment)\b`,
      'gi',
    ),
  },
  {
    kind: 'injection',
    tag: 'jailbreak',
    label: 'Jailbreak / unrestricted-mode phrasing',
    pattern:
      /\b(?:developer mode|dev mode|god mode|debug mode enabled|do anything now|jailbr(?:eak|oken)\w*|unfiltered mode|unrestricted mode|uncensored mode|no[- ]limits? mode|evil (?:mode|confidant)|(?:enable|activate|enter)\s+(?:the\s+)?(?:sudo|admin|root)\s+mode)\b/gi,
  },
  {
    kind: 'injection',
    tag: 'jailbreak',
    label: 'Jailbreak persona (DAN)',
    // Case-sensitive on purpose so the given name "Dan" does not match.
    pattern: /\b(?:DAN|STAN|DUDE)\b(?=[\s,.:;!)]|$)/g,
  },
  {
    kind: 'injection',
    tag: 'roleplay',
    label: 'Asks the model to act as if it has no restrictions',
    pattern: new RegExp(
      String.raw`\b(?:pretend|act as if|act like|imagine|assume|behave as (?:if|though)|role-?play(?: as)?|you are now|from now on,? you(?: are|'re)?)\b${W(5)}\s+(?:(?:no|without|zero|free (?:of|from)|not bound by|unbound by|exempt from|beyond)\s+)(?:\S+\s+){0,2}?(?:restrictions?|rules|limits|limitations|filters|guidelines|safeguards|guardrails|polic(?:y|ies)|constraints|boundaries|ethics|morals|censorship)\b`,
      'gi',
    ),
  },
  {
    kind: 'injection',
    tag: 'roleplay',
    label: 'Claims the model has no restrictions',
    pattern:
      /\byou(?:'re| are)?\s+(?:no longer|not)\s+(?:bound|restricted|limited|constrained)\s+by\b|\byou\s+(?:have|has)\s+no\s+(?:restrictions|rules|limits|filters|guidelines)\b/gi,
  },
  {
    kind: 'injection',
    tag: 'reveal',
    label: 'Requests hidden / system instructions',
    pattern: new RegExp(
      String.raw`\b(?:reveal|show|print|display|output|repeat|disclose|leak|dump|expose|recite|echo|return|list|share|provide|give(?:\s+me)?|tell(?:\s+me)?|write(?:\s+out)?|copy|paste|summari[sz]e|translate|spell out)\b${W(5)}\s+(?:(?:your|the|its|all|any|full|entire|complete|exact|original|initial|hidden|secret|internal|confidential|verbatim|above|previous|prior|developer|system)\s+){0,4}(?:system (?:prompt|message|instructions?)|developer (?:prompt|message|instructions?)|hidden (?:instructions?|prompts?|rules|messages?)|initial (?:prompt|instructions)|original (?:prompt|instructions)|internal (?:instructions|rules|prompt)|secret instructions|meta[- ]?prompt|pre-?prompt|instructions (?:above|you were given|you received)|(?:your|the) (?:instructions|rules|guidelines|configuration)\b(?=\s*(?:verbatim|word for word|exactly|in full|above|$|[.,!?])))`,
      'gi',
    ),
  },
  {
    kind: 'injection',
    tag: 'reveal',
    label: 'Requests hidden / system instructions',
    pattern:
      /\bwhat\s+(?:is|are|were|was)\s+your\s+(?:system prompt|initial (?:prompt|instructions)|instructions|hidden (?:instructions|rules)|rules|original instructions)\b/gi,
  },
  {
    kind: 'injection',
    tag: 'indirect',
    label: 'Tells the model to obey instructions found in external content',
    pattern: new RegExp(
      String.raw`\b(?:follow|obey|execute|run|carry out|comply with|act on|act upon|perform|do|apply|implement|treat)\b\s+(?:(?:any|all|the|whatever|every|each|those|these)\s+){0,2}(?:\S+\s+){0,2}?(?:instructions?|commands?|directives?|tasks?|steps|orders?|requests?)\b${W(4)}\s+(?:in|from|inside|within|contained in|found in|embedded in|on|given (?:in|by)|provided (?:in|by)|returned by|included in)\s+(?:(?:the|this|that|a|an|any|each|every|retrieved|linked|attached|incoming|external)\s+){0,2}(?:\S+\s+){0,2}?(?:web ?pages?|websites?|sites?|pages?|documents?|docs?|files?|pdfs?|e-?mails?|messages?|inbox|tool (?:output|results?|responses?)|function (?:output|results?)|search results?|retrieved (?:content|text|data)|urls?|links?|attachments?|comments?|issues?|tickets?|readmes?|html|content)\b`,
      'gi',
    ),
  },

  // ----------------------------------------------------------------- outbound
  {
    kind: 'outbound',
    tag: 'transmit',
    label: 'Outbound transmission verb',
    pattern:
      /\b(?:send|sends|sending|sent|upload|uploads|uploading|uploaded|publish|publishes|publishing|published|forward|forwards|forwarding|forwarded|transmit|transmits|transmitting|transmitted|exfiltrate|exfiltrates|exfiltrating|exfiltrated|beacon|relay|relays|relaying|relayed|leak|leaks|leaking|submit|submits|submitting|dispatch|deliver|delivers|delivering|push|pushes|pushing|pipe|pipes|piping|sync|syncs|syncing|export|exports|exporting|exported|mail|mails|mailed)\b/gi,
  },
  {
    kind: 'outbound',
    tag: 'transmit',
    label: 'Outbound transmission verb',
    pattern:
      /\b(?:post|posts|posting|posted)\b(?=\s+(?:it|them|this|that|these|those|the|all|every|each|its|their|to|data|a\s+copy|everything|any)\b)/gi,
  },
  {
    kind: 'outbound',
    tag: 'transmit',
    label: 'Outbound transmission verb',
    pattern:
      /\b(?:e-?mail|e-?mails|e-?mailed|e-?mailing|share|shares|sharing|dm)\b(?=\s+(?:it|them|this|that|these|those|the|all|every|each|its|their|a\s+copy|everything|any|my|our|your)\b)/gi,
  },
  {
    kind: 'outbound',
    tag: 'http',
    label: 'HTTP write method',
    // Upper-case only: "POST it to ..." vs the everyday word "post".
    pattern: /\b(?:POST|PUT|PATCH)\b/g,
  },
  {
    kind: 'outbound',
    tag: 'transmit',
    label: 'Outbound transmission verb',
    pattern:
      /\b(?:e-?mail|e-?mails|e-?mailed|e-?mailing|message|messages|messaging|dm|text|share|shares|sharing|shared|copy|copies|copying|write|writes|writing|save|saves|saving|store|stores|storing|log|logs)\b(?=\s+(?:\S+\s+){0,6}?(?:to|with|into|onto|in|at|via)\s+(?:(?:the|a|an|this|that|my|our|their|your|some|following|given|specified|below|above|another|any)\s+)?(?:\S+\s+)?(?:https?:\/\/|[\w.+-]+@[\w-]+\.|external|remote|third[- ]party|outside|attacker|webhook|server|endpoint|url|address|inbox|bucket|storage|pastebin|gist|channel|public|personal))/gi,
  },
  {
    kind: 'outbound',
    tag: 'request',
    label: 'Makes an outbound request',
    pattern:
      /\b(?:make|send|issue|fire|perform|do)\s+(?:an?\s+)?(?:http\s+|https\s+|web\s+|api\s+|network\s+|outbound\s+|get\s+|post\s+)?(?:request|call|ping)s?\s+(?:to|at|against)\b|\b(?:call|hit|ping|curl|wget|invoke|contact|notify)\s+(?:the\s+|this\s+|that\s+|an?\s+|my\s+)?(?:\S+\s+)?(?:webhook|endpoint|url|api|server|callback)\b/gi,
  },
  {
    kind: 'embed',
    tag: 'embed',
    label: 'Embeds data into an outgoing URL, header or request',
    pattern: new RegExp(
      String.raw`\b(?:append|appends|appended|appending|add|adds|added|adding|include|includes|included|including|insert|inserts|inserted|inserting|embed|embeds|embedded|embedding|attach|attaches|attached|attaching|put|puts|putting|place|places|placed|placing|pass|passes|passed|passing|inject|injects|injected|injecting|stuff|smuggle|concatenate|set)\b${W(8)}\s+(?:to|in|into|as|inside|within|onto|on)\s+(?:(?:the|a|an|this|that|each|every|any|all|its|their|your|our|outgoing|outbound|external|http|https|api|next|following|search|image)\s+){0,3}(?:urls?|uris?|links?|query[- ]?strings?|query param(?:eter)?s?|url param(?:eter)?s?|get param(?:eter)?s?|request headers?|http headers?|headers?|requests?|payloads?|request body|body of the request|image (?:url|link|src)|markdown image|search (?:query|queries|terms?|string)|referr?er|cookies?|callback)\b`,
      'gi',
    ),
  },
  {
    kind: 'embed',
    tag: 'embed',
    label: 'Embeds data into an outgoing URL, header or request',
    pattern:
      /\bas\s+(?:an?\s+|the\s+)?(?:query[- ]?(?:string\s+)?param(?:eter)?|url param(?:eter)?|header value|request header|path segment)\b/gi,
  },

  // -------------------------------------------------------------- destination
  {
    kind: 'destination',
    tag: 'url',
    label: 'External URL (shown as inert text)',
    pattern: /\b(?:https?|ftp|sftp|wss?|file):\/\/[^\s<>"'`)\]}]+/gi,
  },
  {
    kind: 'destination',
    tag: 'email',
    label: 'Email address',
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/g,
  },
  {
    kind: 'destination',
    tag: 'ip',
    label: 'Raw IP address',
    pattern: /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b/g,
  },
  {
    kind: 'destination',
    tag: 'domain',
    label: 'Domain name',
    pattern:
      /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|xyz|ru|cn|top|site|online|app|dev|co|info|biz|me|tk|cc|ly|sh|pw|link|click|live|cloud)\b(?:\/[^\s"'<>]*)?/gi,
  },
  {
    kind: 'destination',
    tag: 'webhook',
    label: 'Webhook / collection service',
    pattern:
      /\b(?:webhooks?|web hooks?|webhook\.site|requestbin|request ?catcher|pipedream|ngrok|burp ?collaborator|interactsh|oast|pastebin|hastebin|paste site|hooks\.slack\.com|discord(?:app)?\.com\/api\/webhooks|callback url)\b/gi,
  },
  {
    kind: 'destination',
    tag: 'external',
    label: 'External / third-party destination',
    pattern:
      /\b(?:external|remote|third[- ]party|outside|attacker(?:'s)?|untrusted|unknown|public|personal|offsite|off-site|foreign)\s+(?:\S+\s+)?(?:urls?|uris?|servers?|endpoints?|apis?|hosts?|domains?|sites?|websites?|services?|storage|buckets?|drives?|locations?|addresses?|inbox(?:es)?|accounts?|databases?|repos?(?:itory|itories)?|channels?|parties|party|recipients?|systems?|machines?|destinations?|webhooks?|links?)\b/gi,
  },
  {
    kind: 'destination',
    tag: 'storage',
    label: 'External storage service',
    pattern:
      /\b(?:s3 buckets?|s3:\/\/\S+|public (?:blob|bucket|container)|google drive|dropbox|onedrive|box\.com|wetransfer|github gists?|gists?|ftp servers?|sftp servers?|file[- ]sharing (?:site|service))\b/gi,
  },
  {
    kind: 'destination',
    tag: 'reference',
    label: 'Reference to a destination',
    pattern:
      /\b(?:this|that|the following|following|given|below|above|provided|specified|same|my|our)\s+(?:urls?|uris?|endpoints?|links?|addresses?|servers?|hosts?|apis?|email(?: address)?|inbox|domain)\b|\b(?:email address|e-mail address)\b/gi,
  },
  {
    kind: 'destination',
    tag: 'reference',
    label: 'Reference to a destination',
    pattern: /\bto\s+(?:me|us|my (?:team|colleague|friend))\b(?=\s+(?:at|via)\b)/gi,
  },

  // ---------------------------------------------------------------- sensitive
  {
    kind: 'sensitive',
    tag: 'credential',
    label: 'Credential or secret',
    pattern:
      /\b(?:api[ _-]?keys?|apikeys?|access[ _-]?(?:tokens?|keys?)|refresh[ _-]?tokens?|id[ _-]tokens?|bearer[ _-]?tokens?|auth(?:entication|orization)?[ _-]?(?:tokens?|headers?|codes?|cookies?)|session[ _-]?(?:tokens?|cookies?|ids?)|oauth[ _-]?tokens?|jwts?|json web tokens?|secret[ _-]?keys?|client[ _-]?secrets?|signing[ _-]?keys?|private[ _-]?keys?|ssh[ _-]?keys?|pgp[ _-]?keys?|encryption[ _-]?keys?|master[ _-]?keys?|account[ _-]?keys?|sas[ _-]?tokens?|connection[ _-]?strings?|passwords?(?!\s+(?:reset|policy|policies|manager|strength|complexity|requirements?|rules|field|prompt|expir\w*))|passwd|passphrases?|pins?\b(?=\s+(?:code|number))|credentials?|secrets?(?!\s+of\b)|cookies|tokens?(?=\s+(?:value|string|for|from|in|to|and|$))|keys? vault secrets?|credit card cvv)\b/gi,
  },
  {
    kind: 'sensitive',
    tag: 'environment',
    label: 'Environment / secret store',
    pattern:
      /\b(?:environment variables?|env(?:ironment)? vars?|\.env(?:\.\w+)? files?|\.env\b|process\.env(?:\.\w+)?|os\.environ(?:\[[^\]]*\])?|getenv\(|\$env:\w+|from the environment|key ?vault|secrets? manager|secret store|credential store|keychain|~\/\.ssh\S*|id_rsa|~\/\.aws\/credentials|\/etc\/(?:passwd|shadow)|\.npmrc|\.git-credentials|kubeconfig|appsettings(?:\.\w+)?\.json|web\.config)\b/gi,
  },
  {
    kind: 'sensitive',
    tag: 'prompt',
    label: 'System / developer / hidden instructions',
    pattern:
      /\b(?:system prompts?|system messages?|system instructions?|developer prompts?|developer messages?|developer instructions?|hidden instructions?|hidden prompts?|initial instructions|internal instructions|meta[- ]?prompt|pre-?prompt)\b/gi,
  },
  {
    kind: 'sensitive',
    tag: 'conversation',
    label: 'Conversation / chat history',
    pattern:
      /\b(?:conversation (?:history|logs?|transcripts?|context|so far)|chat (?:history|logs?|transcripts?)|message history|previous messages|prior messages|entire conversation|whole conversation|full conversation|all (?:of )?(?:the|our) (?:messages|conversation)|(?:your|the) (?:memory|context window))\b/gi,
  },
  {
    kind: 'sensitive',
    tag: 'pii',
    label: 'Personal data (PII)',
    pattern:
      /\b(?:pii|personally identifiable information|personal (?:data|information|details)|customer (?:data|records?|information|details|lists?|databases?|emails?|contacts?|pii|accounts?)|user (?:data|records?|information|details|profiles?|database)|client (?:data|records?|information)|employee (?:data|records?|information|details)|social security numbers?|ssns?|national id numbers?|passport numbers?|dates? of birth|home addresses|phone numbers|contact details)\b/gi,
  },
  {
    kind: 'sensitive',
    tag: 'financial',
    label: 'Financial information',
    pattern:
      /\b(?:credit card(?: numbers?| details| data)?|card numbers?|cvv|cvc|bank (?:account|details|statements?|routing)(?: numbers?)?|routing numbers?|iban|swift codes?|financial (?:data|records?|information|statements?|reports?)|payroll(?: data)?|salar(?:y|ies) (?:data|information)|tax returns?|revenue figures)\b/gi,
  },
  {
    kind: 'sensitive',
    tag: 'health',
    label: 'Health information',
    pattern:
      /\b(?:medical (?:records?|history|data|information)|health (?:records?|data|information)|phi|protected health information|patient (?:data|records?|information|charts?)|diagnos(?:is|es)|prescriptions?|lab results)\b/gi,
  },
  {
    kind: 'sensitive',
    tag: 'proprietary',
    label: 'Proprietary code or internal documents',
    pattern:
      /\b(?:proprietary (?:code|source|data|information|algorithms?|models?)|(?:internal|private|confidential|proprietary) (?:source code|code ?base|repos?(?:itory|itories)?)|source code|code ?base|trade secrets?|internal (?:documents?|docs|files|wiki|memos?|reports?|data|emails?)|confidential (?:documents?|files|information|data|reports?|memos?)|private (?:documents?|files)|company secrets|classified (?:documents?|information))\b/gi,
  },

  // ------------------------------------------------------------------- access
  {
    kind: 'access',
    tag: 'access',
    label: 'Data access verb',
    pattern:
      /\b(?:read|reads|reading|get|gets|getting|grab|grabs|retrieve|retrieves|retrieving|extract|extracts|extracting|fetch|fetches|fetching|find|finds|finding|locate|collect|collects|collecting|gather|gathers|gathering|harvest|harvests|harvesting|dump|dumps|dumping|print|prints|printing|show|shows|display|displays|reveal|reveals|revealing|output|outputs|list|lists|listing|enumerate|copy|copies|give me|tell me|access|accesses|accessing|steal|steals|stealing|obtain|obtains|capture|captures|scrape|scrapes|return|returns|expose|exposes|disclose|discloses|look up|search for|pull|pulls|load|loads|cat|echo|exfiltrate|export|include|includes|including)\b/gi,
  },

  // -------------------------------------------------------------- obfuscation
  {
    kind: 'obfuscation',
    tag: 'encode',
    label: 'Encoding / transformation',
    pattern:
      /\b(?:base-?64|b64|base-?32|base-?58|hex(?:adecimal)?(?:-encoded| encoded| encode)?|rot-?13|rot-?47|url-?encod\w*|percent-?encod\w*|uuencod\w*|binary encod\w*|morse code|encode|encodes|encoded|encoding|btoa|atob)\b/gi,
  },
  {
    kind: 'obfuscation',
    tag: 'encrypt',
    label: 'Encryption / encoding before transfer',
    pattern:
      /\b(?:encrypt|encrypts|encrypted|encrypting|xor|cipher|scramble|scrambled|compress and encode)\b/gi,
  },
  {
    kind: 'obfuscation',
    tag: 'reverse',
    label: 'Reversal / character manipulation',
    pattern:
      /\b(?:revers(?:e|ed|ing)\s+(?:the\s+|it|its\s+|each\s+|every\s+)?(?:string|text|order|characters?|letters?|it|value|token|key|secret)?|in reverse(?: order)?|backwards|spell(?:ed)? (?:it )?(?:out )?backwards|character substitution|substitute (?:characters|letters)|swap (?:characters|letters)|leet ?speak|l33t|homoglyphs?|zero[- ]width|insert (?:spaces|dashes|dots) between)\b/gi,
  },
  {
    kind: 'obfuscation',
    tag: 'split',
    label: 'Splitting data into fragments',
    pattern:
      /\b(?:split|splits|splitting|break|chunk|chunks|chunking|fragment|fragments|divide|separate)\b(?:\s+\S+){0,4}?\s+(?:into|across|over|in)\s+(?:\S+\s+){0,2}?(?:parts|pieces|chunks|fragments|segments|multiple (?:requests|messages|calls|parts)|several (?:requests|messages|calls|parts)|separate (?:requests|messages|calls))\b|\bone (?:character|char|letter|byte|digit) at a time\b|\b(?:across|in|over) (?:multiple|several|separate) (?:requests|messages|calls|responses)\b/gi,
  },
  {
    kind: 'obfuscation',
    tag: 'obfuscate',
    label: 'Explicit obfuscation',
    pattern:
      /\b(?:obfuscat\w+|disguis\w+|mask(?:ed|ing)? (?:it|the|as)|steganograph\w*|camouflag\w+)\b/gi,
  },

  // ------------------------------------------------------------- concealment
  {
    kind: 'concealment',
    tag: 'stealth',
    label: 'Covert / silent action',
    pattern:
      /\b(?:silently|quietly|secretly|covertly|stealthily|surreptitiously|discreetly|in the background|behind the scenes|without (?:telling|notifying|informing|alerting|asking|warning|letting) (?:the |any )?(?:user|anyone|them|me|him|her|admins?|administrators?|security)?)\b/gi,
  },
  {
    kind: 'concealment',
    tag: 'nondisclosure',
    label: 'Instruction to hide the action',
    pattern:
      /\b(?:do not|don't|dont|never|must not|mustn't|shouldn't|should not|without)\s+(?:ever\s+)?(?:mention|mentioning|tell|telling|inform|informing|reveal|revealing|disclose|disclosing|say|saying|show|showing|report|reporting|acknowledge|acknowledging|indicate|indicating|alert|alerting|notify|notifying|admit|admitting|let (?:the )?user know)\b(?=\s*(?:$|[.,;!]))|\b(?:do not|don't|dont|never|must not|mustn't|shouldn't|should not|without)\s+(?:ever\s+)?(?:mention|mentioning|tell|telling|inform|informing|reveal|revealing|disclose|disclosing|say|saying|show|showing|report|reporting|acknowledge|acknowledging|indicate|indicating|alert|alerting|notify|notifying|admit|admitting)\s+(?:(?:this|that|it|the action|the request|the upload|the transfer|anything|to the user|the user|them|anyone|what you did|that you|you did|about (?:this|it|that))\b)|\b(?:keep|make) (?:this|it|that) (?:a )?(?:secret|hidden|private|between us|invisible|confidential)\b|\bhide (?:this|it|that|the (?:action|request|fact))\b/gi,
  },
  {
    kind: 'concealment',
    tag: 'evasion',
    label: 'Monitoring / logging evasion',
    pattern:
      /\b(?:do not|don't|dont|never|without)\s+(?:log|logging|record|recording|trace|tracing|audit|auditing|leave (?:a |any )?(?:trace|record|log))\w*\b|\b(?:avoid|evade|escape|bypass|circumvent|dodge|disable|turn off|delete|clear|wipe|erase|tamper with|remove)\s+(?:the\s+|any\s+|all\s+)?(?:detection|monitoring|audit (?:logs?|trails?)|audit|logs?|logging|security (?:monitoring|alerts?|tools?)|dlp|data loss prevention|siem|edr|antivirus|alerts?|telemetry)\b|\bundetect(?:ed|able)\b|\b(?:under|below) the radar\b/gi,
  },
];

// ------------------------------------------------------------ segmentation

const EDUCATIONAL_START =
  /^\s*(?:[-*>#\d.)\s]*)?(?:please\s+|can you\s+|could you\s+)?(?:explain|describe|define|summari[sz]e (?:the )?(?:risks?|concepts?|differences?)|compare|teach|outline|discuss|clarify|what\s+(?:is|are|does|do|was|were|happens|makes|would)|why\b|how\s+(?:do|does|can|could|should|would|is|are|to (?:protect|prevent|secure|detect|mitigate|avoid|defend|store|handle|rotate|manage))|when\s+(?:should|is|do)|is it (?:safe|secure|ok|okay|possible|a good idea)|tell me (?:about|why|how)|help me understand|give (?:me )?an? (?:overview|summary|example) of|list (?:the )?(?:best practices|risks|ways|reasons|common)|write (?:a |an )?(?:blog|article|essay|guide|tutorial|documentation|policy|training)|create (?:a |an )?(?:training|awareness|policy|guide|checklist))\b/i;

const EDUCATIONAL_ANYWHERE =
  /\b(?:best practices?|for example|e\.g\.|such as|an example of|examples of|is an example|security (?:implications|risks?|awareness|training)|risks? of|dangers? of|how to (?:protect|prevent|secure|detect|mitigate|defend|recogni[sz]e|identify)|attackers? (?:might|may|could|often|can|use|try)|malicious (?:users?|actors?|prompts?) (?:might|may|could|often|can|use|try)|(?:does|do|is|are|should) not (?:make|keep|protect)|isn't secure|is not secure|insecure|not secure|why (?:you )?should(?:n't| not)|should never|never (?:put|place|include|store|share|send|commit)|(?:a|an) (?:prompt injection|jailbreak) (?:attack|example|attempt)|prompt injection (?:attacks?|examples?|works?)|detect(?:ing|ion of)? (?:prompt injection|jailbreaks?|exfiltration))\b/i;

/**
 * Splits normalized text into sentence/clause segments. Correlation rules use
 * segment distance as a proximity measure (same clause = strongest).
 */
export function segmentText(text: string): Segment[] {
  const segments: Segment[] = [];
  // Boundaries: sentence punctuation followed by whitespace/end, line breaks,
  // or semicolons. A "." inside a URL or domain is not followed by
  // whitespace, so links are not split.
  const boundary = /[.!?]+(?=\s|$)|\n+|;(?=\s)/g;
  let start = 0;
  const push = (end: number) => {
    const raw = text.slice(start, end);
    if (raw.trim().length > 0) {
      const index = segments.length;
      segments.push({
        index,
        start,
        end,
        text: raw,
        educational: EDUCATIONAL_START.test(raw) || EDUCATIONAL_ANYWHERE.test(raw),
      });
    }
  };
  for (const m of text.matchAll(boundary)) {
    const end = m.index + m[0].length;
    push(end);
    start = end;
  }
  if (start < text.length) push(text.length);
  if (segments.length === 0) {
    segments.push({ index: 0, start: 0, end: text.length, text, educational: false });
  }
  return segments;
}

// ---------------------------------------------------------- signal extraction

const NEGATION_BEFORE =
  /(?:\bnot|n't|\bnever|\bno|\bavoid|\bavoiding|\bwithout|\bprevent|\bpreventing|\bstop|\bforbid|\bprohibit|\brefuse to|\bnor)\b(?:\s+(?!and\b|then\b|but\b)\S+){0,2}\s*$/i;
const TRAILING_PUNCT = /[.,;:!?'"]+$/;

function segmentIndexFor(segments: readonly Segment[], pos: number): number {
  // Binary search for the segment that contains `pos`.
  let lo = 0;
  let hi = segments.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    const seg = segments[mid];
    if (seg && seg.start <= pos) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

export function extractSignals(text: string, segments: readonly Segment[]): Signal[] {
  const signals: Signal[] = [];
  for (const entry of LEXICON) {
    entry.pattern.lastIndex = 0;
    for (const m of text.matchAll(entry.pattern)) {
      let matched = m[0];
      if (entry.kind === 'destination') matched = matched.replace(TRAILING_PUNCT, '');
      if (matched.trim().length === 0) continue;
      const start = m.index;
      const end = start + matched.length;
      const segIdx = segmentIndexFor(segments, start);
      const seg = segments[segIdx];
      const segStart = seg?.start ?? 0;
      const before = text.slice(Math.max(segStart, start - 40), start);
      const quoteCount = (text.slice(segStart, start).match(/"/g) ?? []).length;
      signals.push({
        kind: entry.kind,
        tag: entry.tag,
        label: entry.label,
        start,
        end,
        segment: segIdx,
        // Concealment phrases carry their own negation ("do not mention").
        negated: entry.kind !== 'concealment' && NEGATION_BEFORE.test(before),
        quoted: quoteCount % 2 === 1,
      });
    }
  }
  return dedupeSignals(signals);
}

/**
 * Removes duplicate/overlapping signals of the same kind (e.g. a domain inside
 * a URL, or two lexicon entries matching the same phrase), keeping the longest.
 */
function dedupeSignals(signals: Signal[]): Signal[] {
  signals.sort((a, b) => a.start - b.start || b.end - a.end);
  const kept: Signal[] = [];
  for (const s of signals) {
    const overlap = kept.find((k) => k.kind === s.kind && s.start < k.end && k.start < s.end);
    if (overlap) {
      if (s.end - s.start > overlap.end - overlap.start) kept[kept.indexOf(overlap)] = s;
      continue;
    }
    kept.push(s);
  }
  return kept.sort((a, b) => a.start - b.start);
}
