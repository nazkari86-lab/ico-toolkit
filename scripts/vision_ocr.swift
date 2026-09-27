import Foundation
import ImageIO
import Vision

let imageURL = URL(fileURLWithPath: CommandLine.arguments[1])
guard let imageSource = CGImageSourceCreateWithURL(imageURL as CFURL, nil),
      let image = CGImageSourceCreateImageAtIndex(imageSource, 0, nil) else {
    fputs("cannot read image\n", stderr)
    exit(2)
}

let request = VNRecognizeTextRequest()
request.recognitionLevel = .accurate
request.usesLanguageCorrection = false
request.recognitionLanguages = ["en-US"]

do {
    try VNImageRequestHandler(cgImage: image).perform([request])
    let rows: [[String: Any]] = (request.results ?? []).map { observation in
        let candidates: [[String: Any]] = observation.topCandidates(5).map { candidate in
            ["text": candidate.string, "confidence": candidate.confidence]
        }
        return ["candidates": candidates]
    }
    let data = try JSONSerialization.data(withJSONObject: rows, options: [.sortedKeys])
    FileHandle.standardOutput.write(data)
} catch {
    fputs("Vision OCR failed: \(error)\n", stderr)
    exit(1)
}
