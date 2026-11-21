Machina CAD De-ID

See approch.md for the design, supported formats, and verification commands.
The full track dataset requires a case-sensitive filesystem and space for
139.7 GB of source files, a similarly sized output, and temporary processing.

Run from the project directory.

  bash scripts/get-input.sh --dest ./input --jobs 32
  docker build -t machina-deid ./code
  mkdir -p ./attempt-1 ./private_state
  docker run --rm -v "$PWD/input:/input:ro" -v "$PWD/attempt-1:/attempt" -v "$PWD/private_state:/state" machina-deid run --input /input --output /attempt/corpus --state-dir /state --workers 4 --no-cache --readme-out /attempt/README.txt
  docker run --rm -v "$PWD/attempt-1:/attempt:ro" -v "$PWD/private_state:/state:ro" machina-deid audit --corpus /attempt/corpus --state-dir /state

The run writes an attempt-specific README.txt with its source defects,
omissions, and format warnings. Copy code/ into the attempt alongside
corpus/ and README.txt. Keep the original input, private state, and audit
details outside the attempt.

Local verification used 77 official sample inputs and produced 76 files,
including two zero-byte source files. One password-protected 7z archive
was omitted. The offline Docker audit found zero known identifier matches,
structural failures, or corpus constraint violations in that sample.
A broader WSL run passed the same audit on 217 outputs from 218 inputs.
One RAR archive was omitted after decompression failed.
