# Machina CAD De-ID approach

The Machina buildathon track asks for a de-identified engineering corpus that preserves the usefulness of the CAD models and drawings. The pipeline treats a filename, its model metadata, and references to that file as related surfaces. It processes the local input read-only and writes the transformed files into a separate `corpus/` tree. [Track brief](https://www.joinbuilders.org/buildathon/tracks/machina-deid)

## Discover identities and plan paths

The discovery pass reads source paths, repository and catalog names, and metadata exposed by the supported parsers. It records values such as company names, usernames, domains, author names, project identifiers, and proprietary part numbers. It keeps common engineering terms, dimensions, standards, and format namespaces on allowlists. Distinctive identifiers can apply across the corpus. Ambiguous tokens are matched within their source project.

Metadata reads run concurrently, and the registry allocates pseudonyms in sorted source order. Compound values reuse known components where possible. For example, a synthetic email can use the same username and domain that appear elsewhere. The pipeline then fixes the registry and builds a path map. File handlers can derive a stable pseudonym for an explicit identifier first seen during transformation. This keeps parallel workers from assigning the same counter value to unrelated people or projects.

The path map preserves engineering filenames and suffixes where possible. It updates changed basenames in embedded CAD references when the source-project or unique global mapping resolves them. A boundary-aware literal matcher applies the global and project dictionaries without building a corpus-sized regular expression for every project.

## Transform by format

| Surface | Transformation |
| --- | --- |
| STEP, IGES, and other engineering exchange formats | Stream STEP statements and update selected string fields while keeping numeric entities and topology. Rewrite IGES metadata with valid Hollerith lengths and 80-column records. Treat binary mesh payloads separately from their text headers. |
| Native CAD containers | Rewrite supported OLE property sets, SolidWorks streams, and ZIP-based CAD metadata. Keep untouched model streams and update container offsets or checksums where the rewrite requires it. |
| Drawing PDFs, SVGs, DXFs, and images | Process text, links, metadata, and attachments. Redact PDF text while retaining vector linework. Use OCR for image-based text and replace detected title-block logos with neutral marks. |
| Archives | Walk nested members, sanitize paths and contents, and rebuild the container. Recognized compound suffixes carry through dispatch. Record format conversions and omit inaccessible archives. |

OLE property numbers are interpreted within their property-set identifiers. This keeps engineering properties that share a number with an author or company field intact. Each rewritten stream is addressed by its directory entry so a nested document can have its own set of properties. [Microsoft OLE Property Set specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oleps/92c4329e-9d07-4690-b097-d8adc6a0c7f9)

Workers stage outputs before replacing the destination. Private receipts tie completed writes to the source file, registry, pipeline code, and options. A retry reuses a recorded output when its size and modification time still agree. The optional content cache keys reusable bytes by source content, project, filename, and pipeline settings. Use `--no-cache` to conserve disk on the full corpus.

## Run and verify

Run from the `machina-deid` directory on a case-sensitive Linux filesystem. Use an empty attempt directory for a different input dataset. The official manifest lists 188,722 files and 139.7 GB, so size the filesystem for the input, output, and temporary work.

```bash
bash scripts/get-input.sh --dest ./input --jobs 32
docker build -t machina-deid ./code
mkdir -p attempt-1 private_state

docker run --rm \
  -v "$PWD/input:/input:ro" \
  -v "$PWD/attempt-1:/attempt" \
  -v "$PWD/private_state:/state" \
  machina-deid run --input /input --output /attempt/corpus \
  --state-dir /state --workers 4 --no-cache \
  --readme-out /attempt/README.txt

docker run --rm \
  -v "$PWD/attempt-1:/attempt:ro" \
  -v "$PWD/private_state:/state:ro" \
  machina-deid audit --corpus /attempt/corpus --state-dir /state
```

Substitute `sample_input` for `input` and choose a fresh attempt and state directory to reproduce the smaller run. The audit compares the output paths to the transformation plan, including recorded omissions and conversions. It scans paths and supported parsed fields for discovered identifiers, checks common file framing, and reports object-count and file-size limits. The tests cover STEP geometry, IGES framing, PDF redaction, native CAD metadata, archive recursion, cross-format consistency, and retry behavior.

The 35-test suite passed. An offline Docker run with OCR enabled produced 76 files from 77 official sample inputs. It preserved two empty source files and recorded the omission of one password-protected 7z archive. A second run in WSL produced 217 files from 218 inputs spanning 55 filename suffixes, with one RAR decompression failure recorded as an omission. Both output sets passed the audit with zero known identifier matches, structural failures, or corpus constraint violations. The verified Docker sample is in `sample_output/validated/corpus/`.

The generated `README.txt` records the actual run counts, omissions, and fallback warnings. A submission attempt contains `corpus/`, `code/`, and `README.txt`. Keep the registry, input, cache, and audit details private because they can contain original identifiers. The official uploader uses a short-lived team token.

## Coverage limits

Compressed DWG objects and some undocumented CAD streams have partial metadata coverage. OCR can miss faint, stylized, rotated, or non-Latin text. Targeted whitespace and metadata changes preserve model data by design, while opening proprietary models in their original CAD applications remains a separate verification step. The audit covers known tokens and readable surfaces, including only the framing and adjacent text of very large STEP files. Archive depth and expansion bounds can also produce documented omissions. RAR output uses ZIP and Unix compress output retains `.Z` when `ncompress` is available.
