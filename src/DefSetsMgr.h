// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "DefItem.h"
#include "DefPoint.h"
#include "ReachingDefs.h"


class DefSetsMgr {
public:
	DefSetsMgr();

	RD_ptr& GetPreMinRDs(const BroObj* o) const
		{ return GetRDs(pre_min_defs, o); }
	RD_ptr& GetPostMinRDs(const BroObj* o) const
		{
		if ( HasPostMinRDs(o) )
			return GetRDs(post_min_defs, o);
		else
			return GetPreMinRDs(o);
		}

	RD_ptr& GetRDs(const IntrusivePtr<ReachingDefSet> defs,
				const BroObj* o) const
		{
		return defs->FindRDs(o);
		}

	void SetPreMinRDs(const BroObj* o, RD_ptr& rd)
		{ pre_min_defs->SetRDs(o, rd); }
	void SetPostMinRDs(const BroObj* o, RD_ptr& rd)
		{ post_min_defs->SetRDs(o, rd); }

	void SetEmptyPre(const BroObj* o)
		{
		auto empty_rds = make_new_RD_ptr();
		SetPreMinRDs(o, empty_rds);
		empty_rds.release();
		}

	void SetPreFromPre(const BroObj* target, const BroObj* source)
		{ SetPreMinRDs(target, GetPreMinRDs(source)); }

	void SetPreFromPost(const BroObj* target, const BroObj* source)
		{ SetPreMinRDs(target, GetPostMinRDs(source)); }

	void SetPostFromPre(const BroObj* o)
		{ SetPostMinRDs(o, GetPreMinRDs(o)); }

	void SetPostFromPre(const BroObj* target, const BroObj* source)
		{ SetPostMinRDs(target, GetPreMinRDs(source)); }

	void SetPostFromPost(const BroObj* target, const BroObj* source)
		{ SetPostMinRDs(target, GetPostMinRDs(source)); }

	bool HasPreMinRDs(const BroObj* o) const
		{ return pre_min_defs->HasRDs(o); }

	bool HasPreMinRD(const BroObj* o, const ID* id) const
		{ return pre_min_defs->HasRD(o, id); }

	bool HasPostMinRDs(const BroObj* o) const
		{ return post_min_defs->HasRDs(o); }

	void CreatePreDef(DefinitionItem* di, DefinitionPoint dp);
	void CreatePostDef(const ID* id, DefinitionPoint dp);
	void CreatePostDef(DefinitionItem* di, DefinitionPoint dp);

	void CreateDef(DefinitionItem* di, DefinitionPoint dp, bool is_pre);

	DefinitionItem* GetExprReachingDef(Expr* e)
		{ return item_map.GetExprReachingDef(e); }
	DefinitionItem* GetIDReachingDef(const ID* id)
		{ return item_map.GetIDReachingDef(id); }
        const DefinitionItem* GetConstIDReachingDef(const DefinitionItem* di,
						const char* field_name) const
		{ return item_map.GetConstIDReachingDef(di, field_name); }

protected:
	// Mappings of minimal reaching defs pre- and post- execution
	// of the given object.
	IntrusivePtr<ReachingDefSet> pre_min_defs;
	IntrusivePtr<ReachingDefSet> post_min_defs;

	// Mappings of maximal reaching defs pre- and post- execution
	// of the given object.
	IntrusivePtr<ReachingDefSet> pre_max_defs;
	IntrusivePtr<ReachingDefSet> post_max_defs;

	DefItemMap item_map;
};
