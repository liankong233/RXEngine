# -*- coding: utf-8 -*-
"""Z3 求解扩展：暴露给 JS 沙箱的 require('z3') 门面。"""
try:
    import z3
except ModuleNotFoundError as exc:
    z3 = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


class Z3SolverFacade:
    def __init__(self):
        _require_z3()
        self._solver = z3.Solver()

    def add(self, *constraints):
        self._solver.add(*_constraints(constraints))
        return self

    def check(self):
        return str(self._solver.check())

    def model(self):
        return Z3ModelFacade(self._solver.model())

    def reset(self):
        self._solver.reset()
        return self

    def push(self):
        self._solver.push()
        return self

    def pop(self):
        self._solver.pop()
        return self

    def assertions(self):
        return list(self._solver.assertions())

    def toString(self):
        return str(self._solver)

    def __str__(self):
        return str(self._solver)


class Z3ModelFacade:
    def __init__(self, model):
        self._model = model

    def eval(self, expr, model_completion=False):
        return _to_plain(self._model.eval(expr, model_completion=bool(model_completion)))

    def toString(self):
        return str(self._model)

    def __str__(self):
        return str(self._model)


class Z3Facade:
    def _require_z3(self):
        _require_z3()

    def Solver(self):
        self._require_z3()
        return Z3SolverFacade()

    def Int(self, name):
        self._require_z3()
        return z3.Int(str(name))

    def Bool(self, name):
        return z3.Bool(str(name))

    def Real(self, name):
        return z3.Real(str(name))

    def IntVal(self, value):
        return z3.IntVal(int(value))

    def BoolVal(self, value):
        return z3.BoolVal(bool(value))

    def BitVec(self, name, bits):
        return z3.BitVec(str(name), int(bits))

    def BitVecVal(self, value, bits):
        return z3.BitVecVal(int(value), int(bits))

    def bitvec(self, name, bits):
        return self.BitVec(name, bits)

    def bvv(self, value, bits):
        return self.BitVecVal(value, bits)

    def Eq(self, a, b):
        return a == b

    def Ne(self, a, b):
        return a != b

    def Lt(self, a, b):
        return a < b

    def Le(self, a, b):
        return a <= b

    def Gt(self, a, b):
        return a > b

    def Ge(self, a, b):
        return a >= b

    def ULT(self, a, b):
        return z3.ULT(a, b)

    def ULE(self, a, b):
        return z3.ULE(a, b)

    def UGT(self, a, b):
        return z3.UGT(a, b)

    def UGE(self, a, b):
        return z3.UGE(a, b)

    def Add(self, a, b):
        return a + b

    def Sub(self, a, b):
        return a - b

    def Mul(self, a, b):
        return a * b

    def BVAnd(self, a, b):
        return a & b

    def BVOr(self, a, b):
        return a | b

    def BVXor(self, a, b):
        return a ^ b

    def BVNot(self, a):
        return ~a

    def Shl(self, a, b):
        return a << b

    def LShR(self, a, b):
        return z3.LShR(a, b)

    def Extract(self, high, low, value):
        return z3.Extract(int(high), int(low), value)

    def Concat(self, *values):
        return z3.Concat(*_constraints(values))

    def And(self, *args):
        return z3.And(*_constraints(args))

    def Or(self, *args):
        return z3.Or(*_constraints(args))

    def Not(self, arg):
        return z3.Not(arg)

    def Implies(self, a, b):
        return z3.Implies(a, b)

    def simplify(self, expr):
        return z3.simplify(expr)

    def solve(self, constraints, opts=None):
        return _solve(constraints, opts)

    def isAlwaysTrue(self, expr, opts=None):
        solver = _solver_with_opts(opts)
        solver.add(z3.Not(expr))
        return solver.check() == z3.unsat

    def isAlwaysFalse(self, expr, opts=None):
        solver = _solver_with_opts(opts)
        solver.add(expr)
        return solver.check() == z3.unsat

    def exprToString(self, expr):
        return str(expr)

    def toString(self, obj):
        return str(obj)


def _require_z3():
    if _IMPORT_ERROR is not None:
        raise RuntimeError(f"z3 dependency unavailable: {_IMPORT_ERROR}")


def _constraints(values):
    if len(values) == 1 and isinstance(values[0], (list, tuple)):
        return list(values[0])
    return list(values)


def _solver_with_opts(opts=None):
    _require_z3()
    opts = opts or {}
    solver = z3.Solver()
    if opts.get("timeout") is not None:
        solver.set(timeout=int(float(opts.get("timeout") or 0) * 1000))
    if opts.get("rlimit") is not None:
        solver.set(rlimit=int(opts.get("rlimit") or 0))
    return solver


def _solve(constraints, opts=None):
    solver = _solver_with_opts(opts)
    assertions = _constraints((constraints,))
    try:
        solver.add(*assertions)
        result = solver.check()
        model = _model_dict(solver.model()) if result == z3.sat else {}
        return {
            "ok": True,
            "result": str(result),
            "model": model,
            "assertions": [str(x) for x in assertions],
            "error": None,
        }
    except Exception as exc:
        return {
            "ok": False,
            "result": "error",
            "model": {},
            "assertions": [str(x) for x in assertions],
            "error": {"type": type(exc).__name__, "message": str(exc)},
        }


def _model_dict(model):
    out = {}
    for decl in model.decls():
        out[decl.name()] = _model_value_to_string(model[decl])
    return out


def _model_value_to_string(value):
    if z3.is_bv_value(value):
        bits = value.size()
        width = max(1, (bits + 3) // 4)
        return f"0x{value.as_long():0{width}x}"
    if z3.is_int_value(value):
        return str(value.as_long())
    return str(value)


def _to_plain(value):
    if z3.is_true(value):
        return True
    if z3.is_false(value):
        return False
    if z3.is_int_value(value):
        return value.as_long()
    if z3.is_bv_value(value):
        return _model_value_to_string(value)
    return str(value)
