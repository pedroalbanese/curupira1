# Curupira1 🇧🇷
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/curupira1/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/curupira1?status.png)](http://godoc.org/github.com/pedroalbanese/curupira1)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/curupira1)](https://goreportcard.com/report/github.com/pedroalbanese/curupira1)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/curupira1)](https://github.com/pedroalbanese/curupira1/releases)

### Curupira

Curupira is a 96-bit block cipher, with keys of 96, 144 or 192 bits, and variable number of rounds, an algorithm described at [SBRC 2007](http://albanese.atwebpages.com/documentation/Curupira1_SBRC_2007.pdf) by Paulo S. L. M. Barreto and Marcos A. Simplício Jr., from Universidade de São Paulo (USP) - São Paulo, Brazil.

$$
\text{Curupira}[K] \equiv \sigma[\kappa^{(R)}] \circ \pi \circ \gamma \circ \left( \prod_{r=1}^{R-1} \sigma[\kappa^{(r)}] \circ \theta \circ \pi \circ \gamma \right) \circ \sigma[\kappa^{(0)}]
$$

