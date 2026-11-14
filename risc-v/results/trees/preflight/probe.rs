use leanvm::{Program,Rate};
use leanvm::aggregate::{Tree,TreeShape,LeafShape,Kind};
#[global_allocator] static ALLOCATOR: bench::Counting<bench::Jemalloc> = bench::Counting(bench::Jemalloc);
fn main(){
 parallel::init_with_threads(std::num::NonZeroUsize::new(8).unwrap()).unwrap();
 for leaf_size in [5usize,2,1,10] { let schemes=if leaf_size==5 {vec!["falcon","mldsa"]} else {vec!["falcon"]}; for scheme in schemes {
  let elf=if scheme=="falcon" {falcon_host::ELF}else{mldsa_riscv_host::ELF};let p=Program::from_elf(elf).unwrap();
  let corpus=if scheme=="falcon" {Some(falcon_host::batch(100))}else{None};let mut shape=None;let mut mismatches=0;
  for i in 0..100/leaf_size {
   let advice=if let Some(ref all)=corpus{let mut a=vec![leaf_size as u64];a.extend_from_slice(&all.advice[1+i*leaf_size*201..1+(i+1)*leaf_size*201]);a}else{mldsa_riscv_host::batch_range(i*leaf_size,leaf_size).advice};
   let stats=p.measure(&advice).unwrap();let next=LeafShape::measured(&stats,Rate::MIN);
   if i==0{eprintln!("{} size={} first committed={} cycles={}",scheme,leaf_size,stats.committed,stats.cycles());shape=Some(next)}else if shape!=Some(next){mismatches+=1;eprintln!("{} shape mismatch group {}",scheme,i)}
  }
  eprintln!("{} size={} measured mismatches={}",scheme,leaf_size,mismatches);
  if mismatches>0 {continue}
  let now=std::time::Instant::now();
  match Tree::new(&p,TreeShape{leaf:shape.unwrap(),arity_0:2,arity:2,rate:Rate::MIN,claims:None}) {
   Ok(tree)=>eprintln!("{} TREE_OK setup={} first={} node={} RSS={}",scheme,now.elapsed().as_secs_f64(),tree.stats(Kind::First).committed,tree.stats(Kind::Node).committed,bench::peak_rss_bytes()),
   Err(e)=>eprintln!("{} TREE_ERR {:?}",scheme,e)
  }
 }
}
}
