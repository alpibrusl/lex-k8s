# lex-k8s

**Part of the [Lex](https://lexlang.org) project** — Substrate · [Manifesto](https://lexlang.org/manifesto) · [lex-lang](https://github.com/alpibrusl/lex-lang) · [lex-os](https://github.com/alpibrusl/lex-os) · [lex-iac](https://github.com/alpibrusl/lex-iac)

> A pod spec is a capability request. Kubernetes admits it without ever
> asking what it adds up to.

`lex-os` as a Kubernetes admission wall: a pod spec compiles to typed
effect rows and is checked against the grant governing its namespace,
the way `lex-os check` treats a `.lex` program.

Roadmap and the decision to build only this seam:
[#1](https://github.com/alpibrusl/lex-k8s/issues/1).

## License

[EUPL-1.2](LICENSE).
