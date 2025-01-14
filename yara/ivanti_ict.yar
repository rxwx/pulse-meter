rule Ivanti_ICT_Tool_Detection
{
    meta:
        author = "Rich Warren"
        date = "2024-01-16"
        description = "Detects when the Ivanti Integrity Checker Tool (ICT) has previously logged a detection on the device"
    strings:
        $a = /Integrity Scan Completed: Detected [1-9]\d* new files/
    condition:
        $a
}