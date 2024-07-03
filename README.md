# curupira1
Curupira Block Cipher

### Curupira

Curupira is a 96-bit block cipher, with keys of 96, 144 or 192 bits, and variable number of rounds, an algorithm described at SBRC 2007 by Paulo S. L. M. Barreto and Marcos A. Simplício Jr., from Universidade de São Paulo (USP) - São Paulo, Brazil.

$$
\text{Curupira}[K] \equiv \sigma[\kappa(R)] \circ \pi \circ \gamma \circ \left( \prod_{r=1}^{R-1} \sigma[\kappa(r)] \circ \theta \circ \pi \circ \gamma \right) \circ \sigma[\kappa(0)]
$$

Visit: [github.com/deatil/go-cryptobin](github.com/deatil/go-cryptobin)
