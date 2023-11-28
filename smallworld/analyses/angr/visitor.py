import claripy


class ClaripyVisitor:
    """
    Abstract class for a claripy AST visitor
    """

    def visit_int(self, v, **kwargs):
        raise NotImplementedError(f"{type(self)} missing Integer")

    def visit_bvv(self, v, **kwargs):
        raise NotImplementedError(f"{type(self)} missing BVV")

    def visit_bvs(self, v, **kwargs):
        raise NotImplementedError(f"{type(self)} missing BVS")

    def visit_add(self, v, **kwargs):
        raise NotImplementedError(f"{type(self)} missing Add")

    def visit_concat(self, v, **kwargs):
        raise NotImplementedError(f"{type(self)} missing Concat")

    def visit_extract(self, v, **kwargs):
        raise NotImplementedError(f"{type(self)} missing Extract")

    def visit_if(self, v, **kwargs):
        raise NotImplementedError(f"{type(self)} missing If")

    def visit_reverse(self, v, **kwargs):
        raise NotImplementedError(f"{type(self)} missing Reverse")

    def visit(self, v, **kwargs):
        """
        Perform the visitor pattern on a claripy expression.
        """
        # TODO: This is very far from complete.
        # claripy supports a dizzying array of bitvector operations.
        # It's easier to populate them as I find them.
        if isinstance(v, int):
            # v is a python integer.
            # I occasionally see an int instead of a BVV.
            # I don't exactly know why.
            return self.visit_int(v, **kwargs)
        elif v.op == "BVV":
            # v is a concrete value
            return self.visit_bvv(v, **kwargs)
        elif v.op == "BVS":
            # v is a symbol
            return self.visit_bvs(v, **kwargs)
        elif v.op == "__add__":
            # v = sum(*X), for two or more expressions x in X.
            return self.visit_add(v, **kwargs)
        elif v.op == "Concat":
            # v = Concat(*X), for two or more expressions x in X.
            return self.visit_concat(v, **kwargs)
        elif v.op == "If":
            # v is ITE(x, y, z)
            return self.visit_if(v, **kwargs)
        elif v.op == "Reverse":
            # v is Reverse(x)
            return self.visit_reverse(v, **kwargs)
        elif v.op == "Extract":
            # v is x[a:b], for expression x and ints a and b.
            return self.visit_extract(v, **kwargs)
        else:
            # v is something I haven't thought of yet.
            raise NotImplementedError(f"Unknown op {v.op}")


class ConditionalVisitor(ClaripyVisitor):
    """
    Visitor that splits a conditional expression into its possible evaluations.
    """

    def visit_int(self, v):
        # Integers are leaf ASTs, and never conditional.
        return [v]

    def visit_bvv(self, v):
        # BVVs are leaf ASTs, and never conditional.
        return [v]

    def visit_bvs(self, v):
        # BVSs are leaf ASTs, and never conditional.
        return [v]

    def visit_add(self, v):
        # Addition can produce all combinations of evaluations
        # of the argument expressions.
        out = self.visit(v.args[0])
        for arg in v.args[1:]:
            old_out = out
            out = list()
            for res in self.visit(arg):
                out.extend(list(map(lambda x: x + res, old_out)))
        return out

    def visit_concat(self, v):
        # Concatenation can produce all combinations of evaluations
        # of the argument expressions.
        out = self.visit(v.args[0])
        for arg in v.args[1:]:
            old_out = out
            out = list()
            for res in self.visit(arg):
                out.extend(map(lambda x: x.concat(res), old_out))
        return out

    def visit_extract(self, v):
        # Extraction produces one expression per evaluation
        # of the main argument.  The other two are always ints.
        a = v.args[0]
        b = v.args[1]
        res = list(map(lambda x: x[a:b], self.visit(v.args[2])))
        print(f"Extract: {v.args} -> {res}")
        return res

    def visit_if(self, v):
        # ITE produces the union of the results of
        # the "then" and "else" expressions.
        # The condition itself is ignored.
        out = self.visit(v.args[1])
        out.extend(self.visit(v.args[2]))
        return out

    def visit_reverse(self, v):
        # Reversal produces one expression per evaluation of the argument.
        return list(map(lambda x: claripy.Reverse(x), self.visit(v.args[0])))


class EvalVisitor(ClaripyVisitor):
    def visit_int(self, v, bindings=None):
        return v

    def visit_bvv(self, v, bindings=None):
        return v

    def visit_bvs(self, v, bindings=None):
        if v.args[0] not in bindings:
            raise KeyError("Missing binding for {v}")
        return bindings[v.args[0]]

    def visit_add(self, v, bindings=None):
        # Eval of sum is sum of evals
        out = self.visit(v.args[0], bindings=bindings)
        for x in v.args[1:]:
            out += self.visit(x, bindings=bindings)
        return out

    def visit_concat(self, v, bindings=None):
        # Eval of concat is concat of evals
        return claripy.Concat(map(lambda x: self.visit(x, bindings=bindings), v.args))

    def visit_extract(self, v, bindings=None):
        # Extract only hase one BV argument; the range limits are ints.
        a = v.args[0]
        b = v.args[1]
        return self.visit(v.args[2])[a:b]

    def visit_if(self, v, bindings=None):
        # Concretize all three args of the ITE expression.
        i = self.visit(v.args[0], bindings=bindings)
        t = self.visit(v.args[1], bindings=bindings)
        e = self.visit(v.args[2], bindings=bindings)
        return claripy.If(i, t, e)

    def visit_reverse(self, v, bindings=None):
        # Reverse is a simple unary; reverse the result from the arg.
        return claripy.Reverse(self.visit(v.args[0], bindings=bindings))
