/* All of this stuff should compile with no warnings or errors. However, it's
   currently an incomplete port of my IDAPython version. What needs to happen:
   
   * I need to be able to get the name of a protocol GUID, either by address,
     or by raw byte values of the GUID. I can generate addresses that I think
     are GUIDs, no problem.
   
   * I need to port the logic to get the IDA tinfo_t for the protocol structure.
     The functionality is trivial, but I need to attend to the item above first.
   
   * One function, IsPODArray(), is a stub that I need to finish porting. Again,
     trivial.
   
   * It's not clear how to best integrate this functionality with the rest of
     the plugin. As as right-click Hex-Rays menu item? To be able to be applied
     to all functions in the database? To be able to be applied to any function
     specified by address?
   
   * It's not tested, at all. That's okay, because the rest of the code 
     contains no references to this functionality. It is dead code that will
     never be executed in the present state of affairs. But obviously, before
     it's integrated as user functionality, that will need to change.
*/

#include <pro.h>
#include <lines.hpp>
#include <typeinf.hpp>
#include <hexrays.hpp>

uint32 GetOrdinalByName(const char *name) {
	import_type(get_idati(), -1, name);
	tinfo_t tif;
	if(!tif.get_named_type(get_idati(), name, BTF_STRUCT)) {
		msg("[E] Could not get type named %s\n", name);
		return 0;
	}
	return tif.get_ordinal();
}

bool OffsetOf(tinfo_t tif, const char *name, unsigned int &offset) {
	udt_type_data_t udt;
	if(!tif.get_udt_details(&udt)) {
		qstring str;
		tif.get_type_name(&str);
		msg("[E] Could not retrieve udt_type_data_t for %s\n", str.c_str());
		return false;
	}
	udt_member_t udm;
	udm.name = name;
	int fIdx = tif.find_udt_member(&udm, STRMEM_NAME);
	if(fIdx < 0) {
		qstring str;
		tif.get_type_name(&str);
		msg("[E] Could not find UDT member %s::%s\n", str.c_str(),name);
		return false;
	}
	offset = static_cast<unsigned int>(udt.at(fIdx).offset >> 3ULL);
	return true;
}

// TODO
bool IsPODArray(tinfo_t tif, unsigned int ptrDepth = 0) {
	return false;
}

const char *Expr2String(cexpr_t *e, qstring *out) {
	e->print1(out,NULL);
	tag_remove(out);
	return out->c_str();
}

bool SetHexRaysVariableType(ea_t funcEa, lvar_t &ll, tinfo_t tif) {
	lvar_saved_info_t lsi;
	lsi.ll = ll;
	lsi.type = tif;
	if(!modify_user_lvar_info(funcEa,MLI_TYPE,lsi)) {
		msg("[E] %a: could not modify lvar type for %s\n", funcEa, ll.name.c_str());
		return false;
	}
	return true;
}

struct TargetFunctionPointer {
	char *name;
	int offset;
	unsigned int nArgs;
	unsigned int nGUIDArg;
	unsigned int nOutArg;
	void Clear() {
		name = NULL;
		offset = nArgs = nGUIDArg = nOutArg = 0;
	}
};

struct TargetFunctionPointer BootServicesFunctions[3] {
	{
		"HandleProtocol",
		-1,
		3,
		1,
		2
	},
	{
		"LocateProtocol",
		-1,
		3,
		0,
		2
	},
	{
		"OpenProtocol",
		-1,
		6,
		1,
		2
	}
};

struct TargetFunctionPointer SystemServicesFunctions[2] {
	{
		"SmmHandleProtocol",
		-1,
		3,
		1,
		2		
	},
	{
		"SmmLocateProtocol",
		-1,
		3,
		0,
		2
	},
};

typedef unsigned int uint32;

class ServiceDescriptor {
	protected:
		uint32 mOrdinal;
		tinfo_t mType;
		std::vector<TargetFunctionPointer> mTargets;
		qstring mName;
	public:
		//ServiceDescriptor(uint32 ordinal) : mOrdinal(ordinal) {};
		ServiceDescriptor() : mOrdinal(0) {};

		uint32 GetOrdinal() { return mOrdinal; };
		const char *GetName() { return mName.c_str(); };

		bool InitType(const char *name) {
			import_type(get_idati(), -1, name);
			if(!mType.get_named_type(get_idati(), name, BTF_STRUCT))
				return false;
			mOrdinal = mType.get_ordinal();
			mName = name;
			return true;
		}
		bool InitTargets(TargetFunctionPointer *targets, size_t num) {
			for(int i = 0; i < num; ++i) {
				unsigned int offset;
				if(!OffsetOf(mType, targets[i].name, offset)) {
					msg("[E] Could not get offset of %s\n", targets[i].name);
					return false;
				}
				TargetFunctionPointer &tgt = mTargets.emplace_back();
				tgt = targets[i];
				tgt.offset = offset;
			}
			return true;
		}
		bool LookupOffset(unsigned int offset, TargetFunctionPointer **tgt) {
			for(auto &it : mTargets) {
				if(it.offset == offset) {
					*tgt = &it;
					return true;
				}
			}
			msg("[E] Could not find function pointer with offset %d\n", offset);
			return false;
		}
};

class ServiceDescriptorMap {
	protected:
		std::map<uint32,ServiceDescriptor> mServices;
	public:
		bool Register(ServiceDescriptor &&sd) {
			uint32 ord = sd.GetOrdinal();
			if(mServices.find(ord) != mServices.end()) {
				msg("[E] Ordinal %x already registered\n", ord);
				return false;
			}
			mServices[ord] = std::move(sd);
			return true;
		}
		bool LookupOrdinal(uint32 ord, ServiceDescriptor **sd) {
			auto it = mServices.find(ord);
			if(it == mServices.end()) {
				msg("[E] Could not find ordinal %x\n", ord);
				return false;
			}
			*sd = &it->second;
			return true;
		}
		
		bool LookupOffset(uint32 ord, unsigned int offset, ServiceDescriptor **sd, TargetFunctionPointer **tgt) {
			if(!LookupOrdinal(ord,sd))
				return false;
			if(!(*sd)->LookupOffset(offset,tgt))
				return false;
			return true;
		}
};

class GUIDRelatedVisitorBase : public ctree_visitor_t {
	public:
		GUIDRelatedVisitorBase(ServiceDescriptorMap &m) : 
			ctree_visitor_t(CV_FAST), 
			mDebug(true),
			mServices(m)
			 {};
	protected:
		bool mDebug;
		ServiceDescriptorMap &mServices;
		
		// State variables, cleared on every iteration
		ea_t mEa;
		tinfo_t mTif;
		tinfo_t mTifNoPtr;
		ServiceDescriptor *mpService;
		uint32 mOrdinal;
		unsigned int mOffset;
		TargetFunctionPointer *mpTarget;
		carglist_t *mArgs;
		cexpr_t *mGUIDArg;
		cexpr_t *mOutArg;
		cexpr_t *mGUIDArgRefTo;
		ea_t mGUIDEa;
		void Clear() {
			mEa = BADADDR;
			mTif.clear();
			mTifNoPtr.clear();
			mpService = NULL;
			mOrdinal = 0;
			mOffset = -1;
			mpTarget = NULL;
			mArgs = NULL;
			mGUIDArg = NULL;
			mOutArg = NULL;
			mGUIDArgRefTo = NULL;
			mGUIDEa = BADADDR;
		};
		
		void DebugPrint(const char *fmt, ...) {
			va_list va;
			va_start(va,fmt);
			if(mDebug)
				vmsg(fmt, va);
		};
		
		bool GetICallOrdAndOffset(cexpr_t *e) {
			mEa = e->ea;
			if(e->op != cot_call)
				return false;
			mArgs = e->a;
			cexpr_t *callDest = e->x;
			if(callDest->op == cot_obj)
				return false;
			while(callDest->op == cot_cast)
				callDest = callDest->x;
			if(callDest->op != cot_memptr)
				return false;
			mTif = callDest->x->type;
			if(!mTif.is_ptr()) {
				DebugPrint("%x: variable is not a pointer?\n", mEa);
				return false;
			}
			mTifNoPtr = remove_pointer(mTif);
			mOrdinal = mTifNoPtr.get_ordinal();
			mOffset = callDest->m;
			if(mOrdinal == 0)
				return false;
			return true;
		};
		
		bool ValidateICallDestination() {
			if(!mServices.LookupOffset(mOrdinal,mOffset,&mpService,&mpTarget))
				return false;
			size_t mArgsSize = mArgs->size();
			size_t nArgs = mpTarget->nArgs;
			if(mArgsSize != nArgs) {
				DebugPrint(
					"[E] Call to %s::%s had %d args instead of %d expected\n", 
						mpService->GetName(), 
						mpTarget->name, 
						mArgsSize, 
						nArgs);
				return false;
			}
			mGUIDArg = &mArgs->at(mpTarget->nGUIDArg);
			mOutArg  = &mArgs->at(mpTarget->nOutArg);
			return true;
		};
		
		cexpr_t *GetReferent(cexpr_t *e, const char *desc, bool bAcceptVar) {
			cexpr_t *x = e;
			while(x->op == cot_cast)
				x = x->x;
			
			qstring estr;
			if(bAcceptVar && x->op == cot_var) {
				var_ref_t varRef = x->v;
				lvar_t destVar = varRef.mba->vars[varRef.idx];
				bool bIsPodArray = IsPODArray(destVar.tif,1);
				DebugPrint(
				  "[I] %x Was indirect call from %s::%s, but %s arg was %s, not reference [IsPODArray: %d]",
				  	mEa,
						mpService->GetName(), 
						mpTarget->name, 
						desc,
						Expr2String(e,&estr),
						bIsPodArray);
				return bIsPodArray ? x : NULL;
			}
			
			if(x->op != cot_ref) {
				DebugPrint(
				  "[I] %x Was indirect call from %s::%s, but %s arg was %s, not reference",
				  	mEa,
						mpService->GetName(), 
						mpTarget->name, 
						desc,
						Expr2String(e,&estr));
				return NULL;
			}
			return x->x;
		};
		
		bool ValidateGUIDArgument() {
			mGUIDArgRefTo = GetReferent(mGUIDArg,"GUID",false);
			if(!mGUIDArgRefTo)
				return false;
			
			if(mGUIDArgRefTo->op != cot_obj) {
				qstring estr;
				DebugPrint(
				  "[I] %x Was indirect call from %s::%s, but GUID arg was %s, not reference to global",
				  	mEa,
						mpService->GetName(), 
						mpTarget->name, 
						Expr2String(mGUIDArgRefTo,&estr));
				return false;
			}
			mGUIDEa = mGUIDArgRefTo->obj_ea;
			return true;
		};
		
		bool ValidateCallAndGUID(cexpr_t *e) {
			// Reset all instance variables
			Clear();
			
			// Make sure it's call to something we care about
			if(
				!GetICallOrdAndOffset(e) || 
				!ValidateICallDestination() || 
				!ValidateGUIDArgument())
				return false;
			
			// Good, all checks passed
			return true;
		}		
};

class GUIDRetyper : public GUIDRelatedVisitorBase {
	public:
		GUIDRetyper(ServiceDescriptorMap &m) : 
			GUIDRelatedVisitorBase(m),
			mNumApplied(0)
			{};

		int visit_expr(cexpr_t *e) {
			if(!ValidateCallAndGUID(e))
				return 0;
			
			// Need to look up the GUID here

			// Need to get the type for the GUID variable here
			tinfo_t tifGuidPtr;

			cexpr_t *outArgReferent = GetReferent(mOutArg, "ptr", true);
			if(outArgReferent == NULL)
				return 0;
			ApplyType(outArgReferent,tifGuidPtr);
			return 0;
		}
	protected:
		unsigned int mNumApplied;
		ea_t mFuncEa;
		
		void ApplyType(cexpr_t *outArg, tinfo_t ptrTif) {
			qstring tstr;
			ptrTif.get_type_name(&tstr);
			if(outArg->op == cot_obj) {
				ea_t dest_ea = outArg->ea;
				apply_tinfo(dest_ea, ptrTif, TINFO_DEFINITE);
				++mNumApplied;
				DebugPrint(
					"%x: %s::%s applied type %s\n", 
						mEa,
						mpService->GetName(), 
						mpTarget->name, 
						tstr.c_str());
			}
			else
			if(outArg->op == cot_var) {
				var_ref_t varRef = outArg->v;
				lvar_t &destVar = varRef.mba->vars[varRef.idx];
				if(SetHexRaysVariableType(mFuncEa, destVar, ptrTif)) {
					++mNumApplied;
					DebugPrint(
						"%x: %s::%s applied type %s\n", 
							mEa,
							mpService->GetName(), 
							mpTarget->name, 
							tstr.c_str());
				}
			}
			else {
				qstring estr;
				DebugPrint(
					"%x: %s::%s argument was %s, not global/variable. Could not apply type %s\n", 
						mEa,
						mpService->GetName(), 
						mpTarget->name, 
						Expr2String(outArg,&estr),
						tstr.c_str());
			}
		}
};
