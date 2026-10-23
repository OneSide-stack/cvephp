# Guest assets

Prepared ISO images are placed here by the reproducible image build. They are intentionally ignored by Git because binary artifacts can exceed the session patch budget. `manifest.json` pins their exact byte lengths and SHA-256 digests; the runtime refuses missing or mismatched media.

Build on a Docker-capable x86-64 Linux host with `image-build/build-all.sh`, or run the included GitHub Actions image workflow and download its artifacts. Do not download packages when starting the lab.
