import ast,json,pathlib,sys
p=pathlib.Path(sys.argv[1]); text=p.read_text(encoding='utf-8'); tree=ast.parse(text)
ready_slots=800; using=576; queued=224; missing=0
node=next((n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_needs_device_registration'),None)
if node:
 module=ast.Module(body=[node],type_ignores=[]); ast.fix_missing_locations(module); ns={}; exec(compile(module,str(p),'exec'),ns)
 fn=ns['_needs_device_registration']; registering=sum(fn(True,False) for _ in range(queued)); missing_registering=sum(fn(False,False) for _ in range(5)); no_register=sum(fn(False,True) for _ in range(5)); policy='exact-slot-state'
else:
 marker="state['device_registering'].add(slot)"; start=text.find('async def prepare_slot'); before_gate=text.find(marker,start)<text.find('async with register_gate',start)
 registering=queued if before_gate else 0; missing_registering=5; no_register=5 if before_gate else 0; policy='queued-before-gate'
print(json.dumps({'input':{'registered':ready_slots,'using':using,'queued_ready':queued,'missing':missing},'display_registering':registering,'missing_slots_registering':missing_registering,'no_register_mode_registering':no_register,'policy':policy},ensure_ascii=False,sort_keys=True))
