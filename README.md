# Curupira1 🇧🇷
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/curupira1/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/curupira1?status.png)](http://godoc.org/github.com/pedroalbanese/curupira1)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/curupira1)](https://goreportcard.com/report/github.com/pedroalbanese/curupira1)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/curupira1)](https://github.com/pedroalbanese/curupira1/releases)
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.18570265-blue.svg)](https://doi.org/10.5281/zenodo.18570265)

### Curupira

Curupira is a 96-bit block cipher, with keys of 96, 144 or 192 bits, and variable number of rounds, an algorithm described at [SBRC 2007](http://albanese.atwebpages.com/documentation/Curupira1_SBRC_2007.pdf) by Paulo S. L. M. Barreto and Marcos A. Simplício Jr., from Universidade de São Paulo (USP) - São Paulo, Brazil.

$$
\text{Curupira}[K] \equiv \sigma[\kappa^{(R)}] \circ \pi \circ \gamma \circ \left( \prod_{r=1}^{R-1} \sigma[\kappa^{(r)}] \circ \theta \circ \pi \circ \gamma \right) \circ \sigma[\kappa^{(0)}]
$$

LetterSoup is a two-pass Authenticated Encryption with Associated Data (AEAD) mode of operation designed for high security and efficiency on resource-constrained platforms, such as wireless sensor networks. It is specifically built upon the [MARVIN](https://www.researchgate.net/publication/227604107_The_MARVIN_message_authentication_code_and_the_LETTERSOUP_authenticated_encryption_scheme) message authentication code (which uses the ALRED construction) and the LFSRC mode of operation.
