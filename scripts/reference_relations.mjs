// Reference execution of original Solidity expressions with JavaScript BigInt.
// No SSA nodes, simplification, CSE, or generated Circom are used. Expressions
// retain source scopes and grouping. Reduction is delayed to outputs; integers
// in these bounded-degree polynomials stay small enough for exact BigInt.
import fs from 'node:fs';
const P=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const mod=x=>((x%P)+P)%P;
const source=fs.readFileSync(new URL('../reference/aztec/Relations.sol',import.meta.url),'utf8').replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g,'');
const types=fs.readFileSync(new URL('../reference/aztec/HonkTypes.sol',import.meta.url),'utf8');
const wires=types.match(/enum WIRE\s*\{([^}]+)/)[1].split(',').map(x=>x.trim());
function body(name) {
 let start=source.indexOf('{',source.indexOf('function '+name))+1,end=start,depth=1;
 while(depth){depth+=(source[end]==='{')-(source[end]==='}');end++;}
 return source.slice(start,end-1);
}
const names=['Arithmetic','Permutation','LogDerivativeLookup','DeltaRange','Elliptic','Memory','RomLogup','Nnf','PoseidonExternal','PoseidonInternal'];
const functions=names.map(name=>{
 let b=body('accumulate'+name+'Relation');
 b=b.replace(/\b(0x[0-9a-fA-F]+|\d+)\b/g,'$1n');
 b=b.replace(/wire\(p,\s*WIRE\.(\w+)\)/g,(_,name)=>`p[${wires.indexOf(name)}]`);
 b=b.replace(/Fr\.wrap\(|FrLib\.from\(/g,'mod(');
 b=b.replace(/Fr\[\d+n\]\s+memory\s+(\w+)/g,'let $1');
 b=b.replace(/\bFr\s+(\w+)\s*;/g,'let $1=0n;');
 b=b.replace(/\bFr\s+/g,'let ');
 b=b.replace(/\b\w+Params\s+memory\s+(\w+)\s*;/g,'let $1={};');
 return new Function('p','rp','evals','domainSep','mod','ZERO','ONE','MINUS_ONE','GRUMPKIN_CURVE_B_PARAMETER_NEGATED','NEG_HALF_MODULO_P','LIMB_SIZE','SUBLIMB_SHIFT',b);
});
export function relationOracle(input) {
 const {p,eta,romLogupGamma,beta,gamma,publicInputsDelta,domainSep,alpha}=input;
 const evals=Array(31).fill(0n),rp={eta,romLogupGamma,beta,gamma,publicInputsDelta};
 for(const f of functions) f(p,rp,evals,domainSep,mod,0n,1n,P-1n,17n,(P-1n)/2n,1n<<68n,1n<<14n);
 const evaluations=evals.map(mod);
 let batched=0n;
 for(let i=30;i>=0;i--)batched=mod(batched*alpha+evaluations[i]);
 return {evaluations,batched};
}

// Regenerate the deterministic nonzero vectors used by the Go regression test.
if (process.argv.includes('--write-vectors')) {
 let state=123456789n;
 const random=()=>state=(state*6364136223846793005n+1442695040888963407n)%P;
 const vectors=[];
 for(let k=0;k<24;k++) {
  const p=Array.from({length:41},random), fields=Array.from({length:7},random);
  const [eta,romLogupGamma,beta,gamma,publicInputsDelta,domainSep,alpha]=fields;
  const out=relationOracle({p,eta,romLogupGamma,beta,gamma,publicInputsDelta,domainSep,alpha});
  vectors.push({p:p.map(String),fields:fields.map(String),expected:String(out.batched)});
 }
 fs.writeFileSync(new URL('../scalar/testdata/solidity-relations.json',import.meta.url),JSON.stringify(vectors));
}
