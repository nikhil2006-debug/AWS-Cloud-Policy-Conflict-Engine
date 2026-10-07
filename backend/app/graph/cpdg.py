"""Cloud Policy Dependency Graph: nodes = principals / policy statements / resources."""


class CPDG:
    def __init__(self):
        self.nodes = {}
        self.edges = []

    # ---- ids ----
    @staticmethod
    def principal_node_id(p):
        return f"principal:{p}"

    @staticmethod
    def resource_node_id(arn):
        if arn.startswith("arn:aws:s3:::"):
            return "s3:" + arn[len("arn:aws:s3:::"):].split("/")[0]
        return f"resource:{arn}"

    @staticmethod
    def _resource_type_label(arn):
        if arn.startswith("arn:aws:s3:::"):
            return "S3_BUCKET", arn[len("arn:aws:s3:::"):].split("/")[0]
        return "RESOURCE", arn

    # ---- building ----
    def add_node(self, nid, ntype, label, **attrs):
        self.nodes.setdefault(nid, {"id": nid, "type": ntype, "label": label, **attrs})

    def add_edge(self, src, dst, relation, **attrs):
        self.edges.append({"source": src, "target": dst, "relation": relation, **attrs})

    def build(self, statements):
        for s in statements:
            pid = self.principal_node_id(s["principal"])
            ptype = "IAM_ROLE" if s["principal"] != "*" else "ANY_PRINCIPAL"
            self.add_node(pid, ptype, s["principal"])
            self.add_node(s["statement_id"], "IAM_POLICY", s["policy_id"],
                          effect=s["effect"], principal=s["principal"], policy_name=s["policy_name"])
            self.add_edge(pid, s["statement_id"], "ATTACHED_TO")
            for r in s["resources"]:
                rtype, label = self._resource_type_label(r)
                rid = self.resource_node_id(r)
                self.add_node(rid, rtype, label)
                self.add_edge(s["statement_id"], rid, "TARGETS", actions=s["actions"], effect=s["effect"])
        return self

    def add_conflict_edge(self, allow_id, deny_id):
        self.add_edge(allow_id, deny_id, "CONFLICTS_WITH")

    # ---- queries ----
    def principals_with_access(self, resource_node):
        """Distinct principals with an Allow statement targeting this resource (dependency count)."""
        found = set()
        for e in self.edges:
            if e["relation"] == "TARGETS" and e["target"] == resource_node and e["effect"] == "Allow":
                found.add(self.nodes[e["source"]]["principal"])
        return len(found)

    def subgraph(self, conflict):
        a, d = conflict["allow"], conflict["deny"]
        ids = {self.principal_node_id(a["principal"]), self.principal_node_id(d["principal"]),
               a["statement_id"], d["statement_id"]}
        for o in conflict["overlaps"]:
            ids.add(self.resource_node_id(o["allow_resource"]))
            ids.add(self.resource_node_id(o["deny_resource"]))
        return {
            "nodes": [self.nodes[i] for i in ids if i in self.nodes],
            "edges": [e for e in self.edges if e["source"] in ids and e["target"] in ids],
        }