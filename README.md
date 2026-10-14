# BrandWatch · static demo

A read-only copy of the BrandWatch demo (fictional brands only), served by Cloudflare from `public/`.
It is generated, not edited: on the `main` branch run the demo server, then

```
python scripts/build_static_demo.py --base http://127.0.0.1:8765 --out site
```

and copy `site/` to `public/` here. The source code, the README and how to run the full app: the `main` branch.
