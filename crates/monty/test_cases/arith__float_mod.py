# === Float modulo: Python uses floored division (result sign matches divisor) ===

# Positive dividend, positive divisor
assert 7.5 % 2.0 == 1.5, 'positive % positive'
assert 10.0 % 3.0 == 1.0, 'positive % positive integer result'

# Negative dividend, positive divisor — result must be positive
assert -7.0 % 3.0 == 2.0, 'negative % positive'
assert -1.0 % 10.0 == 9.0, 'negative % large positive'
assert -0.5 % 1.0 == 0.5, 'small negative % positive'

# Positive dividend, negative divisor — result must be negative
assert 7.0 % -3.0 == -2.0, 'positive % negative'
assert 1.0 % -10.0 == -9.0, 'positive % large negative'

# Negative dividend, negative divisor — result must be negative
assert -7.0 % -3.0 == -1.0, 'negative % negative'

# === Mixed int/float operands ===
assert -7 % 3.0 == 2.0, 'negative int % positive float'
assert 7.0 % -3 == -2.0, 'positive float % negative int'
assert -1 % 10.0 == 9.0, 'negative int % positive float large'

# === Edge cases ===
assert 0.0 % 5.0 == 0.0, 'zero % positive'
assert 0.0 % -5.0 == 0.0, 'zero % negative (should not be -0.0 per CPython)'
assert -0.0 % 5.0 == 0.0, 'negative zero % positive'
