Digital Evidence Triage Tool
Why I’m Building Tools for War Crime Investigation:

Thousands of videos and photos are uploaded to Telegram and Twitter every day from conflict zones. The problem isn't finding evidence; it's proving that what we’re looking at is real. As an engineering student, I realized that my most valuable contribution isn't just passion but building the technical "filters" that help investigators find the truth in a sea of data. That's the reason I made this passion project: "Digital Evidence Triage Tool."
Cryptographic Preservation First

In forensics, the most dangerous moment for a piece of evidence is the first time you touch it. If an investigator opens a file and accidentally saves a change, the metadata changes, and a defense lawyer could get that evidence thrown out of court. I tackled this by building a hashing system right into the start of my script. Before my code even looks at what’s in the file, it generates a SHA-256 hash. It’s like a digital fingerprint.

I made sure the script reads the file in "chunks" (small 4KB blocks) so it doesn't crash a normal laptop when processing hours of heavy footage. Furthermore, when dealing with OSINT platforms like Telegram that strip EXIF data, this hash becomes our primary method for deduplicating files and tracking the spread of an image across different channels.
Beyond File Extensions

One of the first things you learn in security is that file names are just labels, and labels lie. Anyone can rename a malicious script or a hidden document to evidence.jpg. I decided my tool shouldn't care about the file extension at all.

Instead of writing custom magic-number checkers, my tool leverages libmagic (the industry standard for file identification). It reads the raw bytes at the start of the file’s header to determine its true MIME type. If a file claims to be a JPEG but is actually a disguised executable, the tool flags it immediately.
Deep Metadata Extraction via ExifTool

Extracting GPS data from images is notoriously messy—coordinates are often stored in complex "Rational" fractions. Furthermore, handling metadata across hundreds of different video and image formats requires a massive framework.

Instead of relying on basic Python image libraries, this tool acts as a wrapper for Phil Harvey’s ExifTool, the undisputed industry standard for digital forensics. My script feeds files to ExifTool, extracts the complete internal metadata, and automatically formats raw GPS fractions into clean Decimal Degrees. This means an investigator can take the JSON output of my script, drop the coordinates into Google Maps, and instantly see the exact street corner where the photo was taken, alongside the precise DateTimeOriginal of the sensor capture.
Built for Scale

War crime investigations don't deal with dozens of photos; they deal with tens of thousands. Processing these sequentially is not an option. I engineered the tool using concurrent processing (ThreadPoolExecutor), allowing it to scan and process massive directories of evidence simultaneously across multiple CPU threads, drastically reducing triage time.
Next steps

This is just the beginning. Right now, the tool handles the "basics," but I am actively looking into:

    Database Integration: Transitioning the JSON report output into a relational database (like SQLite) to build a searchable registry of OSINT data.

    Error Level Analysis (ELA): Adding visual analysis to look at how pixels are compressed, helping to identify if someone digitally added or removed an object into a scene after the fact.

I’m not a lawyer or a field investigator yet, but I am an engineer. And in 2026, building the code that protects the integrity of the truth is one of the most important ways to fight for justice.
