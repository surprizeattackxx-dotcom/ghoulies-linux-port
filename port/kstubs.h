// AUTO-GENERATED from scripts/xboxkrnl_ordinals.tsv. Do not hand-edit.
// One stub per xboxkrnl.exe ordinal (1..378). Every stub just reports which
// kernel function the game actually called and exits - this is a "which function
// do I need to implement next" instrument, not a kernel reimplementation yet.
#ifndef KSTUBS_H
#define KSTUBS_H

void kstub_hit(int ordinal, const char *name);

static void stub_1(void) { kstub_hit(1, "AvGetSavedDataAddress"); }
static void stub_2(void) { kstub_hit(2, "AvSendTVEncoderOption"); }
static void stub_3(void) { kstub_hit(3, "AvSetDisplayMode"); }
static void stub_4(void) { kstub_hit(4, "AvSetSavedDataAddress"); }
static void stub_5(void) { kstub_hit(5, "DbgBreakPoint"); }
static void stub_6(void) { kstub_hit(6, "DbgBreakPointWithStatus"); }
static void stub_7(void) { kstub_hit(7, "DbgLoadImageSymbols"); }
static void stub_8(void) { kstub_hit(8, "DbgPrint"); }
static void stub_9(void) { kstub_hit(9, "HalReadSMCTrayState"); }
static void stub_10(void) { kstub_hit(10, "DbgPrompt"); }
static void stub_11(void) { kstub_hit(11, "DbgUnLoadImageSymbols"); }
static void stub_12(void) { kstub_hit(12, "ExAcquireReadWriteLockExclusive"); }
static void stub_13(void) { kstub_hit(13, "ExAcquireReadWriteLockShared"); }
static void stub_14(void) { kstub_hit(14, "ExAllocatePool"); }
static void stub_15(void) { kstub_hit(15, "ExAllocatePoolWithTag"); }
static void stub_16(void) { kstub_hit(16, "ExEventObjectType"); }
static void stub_17(void) { kstub_hit(17, "ExFreePool"); }
static void stub_18(void) { kstub_hit(18, "ExInitializeReadWriteLock"); }
static void stub_19(void) { kstub_hit(19, "ExInterlockedAddLargeInteger"); }
static void stub_20(void) { kstub_hit(20, "ExInterlockedAddLargeStatistic"); }
static void stub_21(void) { kstub_hit(21, "ExInterlockedCompareExchange64"); }
static void stub_22(void) { kstub_hit(22, "ExMutantObjectType"); }
static void stub_23(void) { kstub_hit(23, "ExQueryPoolBlockSize"); }
static void stub_24(void) { kstub_hit(24, "ExQueryNonVolatileSetting"); }
static void stub_25(void) { kstub_hit(25, "ExReadWriteRefurbInfo"); }
static void stub_26(void) { kstub_hit(26, "ExRaiseException"); }
static void stub_27(void) { kstub_hit(27, "ExRaiseStatus"); }
static void stub_28(void) { kstub_hit(28, "ExReleaseReadWriteLock"); }
static void stub_29(void) { kstub_hit(29, "ExSaveNonVolatileSetting"); }
static void stub_30(void) { kstub_hit(30, "ExSemaphoreObjectType"); }
static void stub_31(void) { kstub_hit(31, "ExTimerObjectType"); }
static void stub_32(void) { kstub_hit(32, "ExfInterlockedInsertHeadList"); }
static void stub_33(void) { kstub_hit(33, "ExfInterlockedInsertTailList"); }
static void stub_34(void) { kstub_hit(34, "ExfInterlockedRemoveHeadList"); }
static void stub_35(void) { kstub_hit(35, "FscGetCacheSize"); }
static void stub_36(void) { kstub_hit(36, "FscInvalidateIdleBlocks"); }
static void stub_37(void) { kstub_hit(37, "FscSetCacheSize"); }
static void stub_38(void) { kstub_hit(38, "HalClearSoftwareInterrupt"); }
static void stub_39(void) { kstub_hit(39, "HalDisableSystemInterrupt"); }
static void stub_40(void) { kstub_hit(40, "HalDiskCachePartitionCount"); }
static void stub_41(void) { kstub_hit(41, "HalDiskModelNumber"); }
static void stub_42(void) { kstub_hit(42, "HalDiskSerialNumber"); }
static void stub_43(void) { kstub_hit(43, "HalEnableSystemInterrupt"); }
static void stub_44(void) { kstub_hit(44, "HalGetInterruptVector"); }
static void stub_45(void) { kstub_hit(45, "HalReadSMBusValue"); }
static void stub_46(void) { kstub_hit(46, "HalReadWritePCISpace"); }
static void stub_47(void) { kstub_hit(47, "HalRegisterShutdownNotification"); }
static void stub_48(void) { kstub_hit(48, "HalRequestSoftwareInterrupt"); }
static void stub_49(void) { kstub_hit(49, "HalReturnToFirmware"); }
static void stub_50(void) { kstub_hit(50, "HalWriteSMBusValue"); }
static void stub_51(void) { kstub_hit(51, "InterlockedCompareExchange"); }
static void stub_52(void) { kstub_hit(52, "InterlockedDecrement"); }
static void stub_53(void) { kstub_hit(53, "InterlockedIncrement"); }
static void stub_54(void) { kstub_hit(54, "InterlockedExchange"); }
static void stub_55(void) { kstub_hit(55, "InterlockedExchangeAdd"); }
static void stub_56(void) { kstub_hit(56, "InterlockedFlushSList"); }
static void stub_57(void) { kstub_hit(57, "InterlockedPopEntrySList"); }
static void stub_58(void) { kstub_hit(58, "InterlockedPushEntrySList"); }
static void stub_59(void) { kstub_hit(59, "IoAllocateIrp"); }
static void stub_60(void) { kstub_hit(60, "IoBuildAsynchronousFsdRequest"); }
static void stub_61(void) { kstub_hit(61, "IoBuildDeviceIoControlRequest"); }
static void stub_62(void) { kstub_hit(62, "IoBuildSynchronousFsdRequest"); }
static void stub_63(void) { kstub_hit(63, "IoCheckShareAccess"); }
static void stub_64(void) { kstub_hit(64, "IoCompletionObjectType"); }
static void stub_65(void) { kstub_hit(65, "IoCreateDevice"); }
static void stub_66(void) { kstub_hit(66, "IoCreateFile"); }
static void stub_67(void) { kstub_hit(67, "IoCreateSymbolicLink"); }
static void stub_68(void) { kstub_hit(68, "IoDeleteDevice"); }
static void stub_69(void) { kstub_hit(69, "IoDeleteSymbolicLink"); }
static void stub_70(void) { kstub_hit(70, "IoDeviceObjectType"); }
static void stub_71(void) { kstub_hit(71, "IoFileObjectType"); }
static void stub_72(void) { kstub_hit(72, "IoFreeIrp"); }
static void stub_73(void) { kstub_hit(73, "IoInitializeIrp"); }
static void stub_74(void) { kstub_hit(74, "IoInvalidDeviceRequest"); }
static void stub_75(void) { kstub_hit(75, "IoQueryFileInformation"); }
static void stub_76(void) { kstub_hit(76, "IoQueryVolumeInformation"); }
static void stub_77(void) { kstub_hit(77, "IoQueueThreadIrp"); }
static void stub_78(void) { kstub_hit(78, "IoRemoveShareAccess"); }
static void stub_79(void) { kstub_hit(79, "IoSetIoCompletion"); }
static void stub_80(void) { kstub_hit(80, "IoSetShareAccess"); }
static void stub_81(void) { kstub_hit(81, "IoStartNextPacket"); }
static void stub_82(void) { kstub_hit(82, "IoStartNextPacketByKey"); }
static void stub_83(void) { kstub_hit(83, "IoStartPacket"); }
static void stub_84(void) { kstub_hit(84, "IoSynchronousDeviceIoControlRequest"); }
static void stub_85(void) { kstub_hit(85, "IoSynchronousFsdRequest"); }
static void stub_86(void) { kstub_hit(86, "IofCallDriver"); }
static void stub_87(void) { kstub_hit(87, "IofCompleteRequest"); }
static void stub_88(void) { kstub_hit(88, "KdDebuggerEnabled"); }
static void stub_89(void) { kstub_hit(89, "KdDebuggerNotPresent"); }
static void stub_90(void) { kstub_hit(90, "IoDismountVolume"); }
static void stub_91(void) { kstub_hit(91, "IoDismountVolumeByName"); }
static void stub_92(void) { kstub_hit(92, "KeAlertResumeThread"); }
static void stub_93(void) { kstub_hit(93, "KeAlertThread"); }
static void stub_94(void) { kstub_hit(94, "KeBoostPriorityThread"); }
static void stub_95(void) { kstub_hit(95, "KeBugCheck"); }
static void stub_96(void) { kstub_hit(96, "KeBugCheckEx"); }
static void stub_97(void) { kstub_hit(97, "KeCancelTimer"); }
static void stub_98(void) { kstub_hit(98, "KeConnectInterrupt"); }
static void stub_99(void) { kstub_hit(99, "KeDelayExecutionThread"); }
static void stub_100(void) { kstub_hit(100, "KeDisconnectInterrupt"); }
static void stub_101(void) { kstub_hit(101, "KeEnterCriticalRegion"); }
static void stub_102(void) { kstub_hit(102, "MmGlobalData"); }
static void stub_103(void) { kstub_hit(103, "KeGetCurrentIrql"); }
static void stub_104(void) { kstub_hit(104, "KeGetCurrentThread"); }
static void stub_105(void) { kstub_hit(105, "KeInitializeApc"); }
static void stub_106(void) { kstub_hit(106, "KeInitializeDeviceQueue"); }
static void stub_107(void) { kstub_hit(107, "KeInitializeDpc"); }
static void stub_108(void) { kstub_hit(108, "KeInitializeEvent"); }
static void stub_109(void) { kstub_hit(109, "KeInitializeInterrupt"); }
static void stub_110(void) { kstub_hit(110, "KeInitializeMutant"); }
static void stub_111(void) { kstub_hit(111, "KeInitializeQueue"); }
static void stub_112(void) { kstub_hit(112, "KeInitializeSemaphore"); }
static void stub_113(void) { kstub_hit(113, "KeInitializeTimerEx"); }
static void stub_114(void) { kstub_hit(114, "KeInsertByKeyDeviceQueue"); }
static void stub_115(void) { kstub_hit(115, "KeInsertDeviceQueue"); }
static void stub_116(void) { kstub_hit(116, "KeInsertHeadQueue"); }
static void stub_117(void) { kstub_hit(117, "KeInsertQueue"); }
static void stub_118(void) { kstub_hit(118, "KeInsertQueueApc"); }
static void stub_119(void) { kstub_hit(119, "KeInsertQueueDpc"); }
static void stub_120(void) { kstub_hit(120, "KeInterruptTime"); }
static void stub_121(void) { kstub_hit(121, "KeIsExecutingDpc"); }
static void stub_122(void) { kstub_hit(122, "KeLeaveCriticalRegion"); }
static void stub_123(void) { kstub_hit(123, "KePulseEvent"); }
static void stub_124(void) { kstub_hit(124, "KeQueryBasePriorityThread"); }
static void stub_125(void) { kstub_hit(125, "KeQueryInterruptTime"); }
static void stub_126(void) { kstub_hit(126, "KeQueryPerformanceCounter"); }
static void stub_127(void) { kstub_hit(127, "KeQueryPerformanceFrequency"); }
static void stub_128(void) { kstub_hit(128, "KeQuerySystemTime"); }
static void stub_129(void) { kstub_hit(129, "KeRaiseIrqlToDpcLevel"); }
static void stub_130(void) { kstub_hit(130, "KeRaiseIrqlToSynchLevel"); }
static void stub_131(void) { kstub_hit(131, "KeReleaseMutant"); }
static void stub_132(void) { kstub_hit(132, "KeReleaseSemaphore"); }
static void stub_133(void) { kstub_hit(133, "KeRemoveByKeyDeviceQueue"); }
static void stub_134(void) { kstub_hit(134, "KeRemoveDeviceQueue"); }
static void stub_135(void) { kstub_hit(135, "KeRemoveEntryDeviceQueue"); }
static void stub_136(void) { kstub_hit(136, "KeRemoveQueue"); }
static void stub_137(void) { kstub_hit(137, "KeRemoveQueueDpc"); }
static void stub_138(void) { kstub_hit(138, "KeResetEvent"); }
static void stub_139(void) { kstub_hit(139, "KeRestoreFloatingPointState"); }
static void stub_140(void) { kstub_hit(140, "KeResumeThread"); }
static void stub_141(void) { kstub_hit(141, "KeRundownQueue"); }
static void stub_142(void) { kstub_hit(142, "KeSaveFloatingPointState"); }
static void stub_143(void) { kstub_hit(143, "KeSetBasePriorityThread"); }
static void stub_144(void) { kstub_hit(144, "KeSetDisableBoostThread"); }
static void stub_145(void) { kstub_hit(145, "KeSetEvent"); }
static void stub_146(void) { kstub_hit(146, "KeSetEventBoostPriority"); }
static void stub_147(void) { kstub_hit(147, "KeSetPriorityProcess"); }
static void stub_148(void) { kstub_hit(148, "KeSetPriorityThread"); }
static void stub_149(void) { kstub_hit(149, "KeSetTimer"); }
static void stub_150(void) { kstub_hit(150, "KeSetTimerEx"); }
static void stub_151(void) { kstub_hit(151, "KeStallExecutionProcessor"); }
static void stub_152(void) { kstub_hit(152, "KeSuspendThread"); }
static void stub_153(void) { kstub_hit(153, "KeSynchronizeExecution"); }
static void stub_154(void) { kstub_hit(154, "KeSystemTime"); }
static void stub_155(void) { kstub_hit(155, "KeTestAlertThread"); }
static void stub_156(void) { kstub_hit(156, "KeTickCount"); }
static void stub_157(void) { kstub_hit(157, "KeTimeIncrement"); }
static void stub_158(void) { kstub_hit(158, "KeWaitForMultipleObjects"); }
static void stub_159(void) { kstub_hit(159, "KeWaitForSingleObject"); }
static void stub_160(void) { kstub_hit(160, "KfRaiseIrql"); }
static void stub_161(void) { kstub_hit(161, "KfLowerIrql"); }
static void stub_162(void) { kstub_hit(162, "KiBugCheckData"); }
static void stub_163(void) { kstub_hit(163, "KiUnlockDispatcherDatabase"); }
static void stub_164(void) { kstub_hit(164, "LaunchDataPage"); }
static void stub_165(void) { kstub_hit(165, "MmAllocateContiguousMemory"); }
static void stub_166(void) { kstub_hit(166, "MmAllocateContiguousMemoryEx"); }
static void stub_167(void) { kstub_hit(167, "MmAllocateSystemMemory"); }
static void stub_168(void) { kstub_hit(168, "MmClaimGpuInstanceMemory"); }
static void stub_169(void) { kstub_hit(169, "MmCreateKernelStack"); }
static void stub_170(void) { kstub_hit(170, "MmDeleteKernelStack"); }
static void stub_171(void) { kstub_hit(171, "MmFreeContiguousMemory"); }
static void stub_172(void) { kstub_hit(172, "MmFreeSystemMemory"); }
static void stub_173(void) { kstub_hit(173, "MmGetPhysicalAddress"); }
static void stub_174(void) { kstub_hit(174, "MmIsAddressValid"); }
static void stub_175(void) { kstub_hit(175, "MmLockUnlockBufferPages"); }
static void stub_176(void) { kstub_hit(176, "MmLockUnlockPhysicalPage"); }
static void stub_177(void) { kstub_hit(177, "MmMapIoSpace"); }
static void stub_178(void) { kstub_hit(178, "MmPersistContiguousMemory"); }
static void stub_179(void) { kstub_hit(179, "MmQueryAddressProtect"); }
static void stub_180(void) { kstub_hit(180, "MmQueryAllocationSize"); }
static void stub_181(void) { kstub_hit(181, "MmQueryStatistics"); }
static void stub_182(void) { kstub_hit(182, "MmSetAddressProtect"); }
static void stub_183(void) { kstub_hit(183, "MmUnmapIoSpace"); }
static void stub_184(void) { kstub_hit(184, "NtAllocateVirtualMemory"); }
static void stub_185(void) { kstub_hit(185, "NtCancelTimer"); }
static void stub_186(void) { kstub_hit(186, "NtClearEvent"); }
static void stub_187(void) { kstub_hit(187, "NtClose"); }
static void stub_188(void) { kstub_hit(188, "NtCreateDirectoryObject"); }
static void stub_189(void) { kstub_hit(189, "NtCreateEvent"); }
static void stub_190(void) { kstub_hit(190, "NtCreateFile"); }
static void stub_191(void) { kstub_hit(191, "NtCreateIoCompletion"); }
static void stub_192(void) { kstub_hit(192, "NtCreateMutant"); }
static void stub_193(void) { kstub_hit(193, "NtCreateSemaphore"); }
static void stub_194(void) { kstub_hit(194, "NtCreateTimer"); }
static void stub_195(void) { kstub_hit(195, "NtDeleteFile"); }
static void stub_196(void) { kstub_hit(196, "NtDeviceIoControlFile"); }
static void stub_197(void) { kstub_hit(197, "NtDuplicateObject"); }
static void stub_198(void) { kstub_hit(198, "NtFlushBuffersFile"); }
static void stub_199(void) { kstub_hit(199, "NtFreeVirtualMemory"); }
static void stub_200(void) { kstub_hit(200, "NtFsControlFile"); }
static void stub_201(void) { kstub_hit(201, "NtOpenDirectoryObject"); }
static void stub_202(void) { kstub_hit(202, "NtOpenFile"); }
static void stub_203(void) { kstub_hit(203, "NtOpenSymbolicLinkObject"); }
static void stub_204(void) { kstub_hit(204, "NtProtectVirtualMemory"); }
static void stub_205(void) { kstub_hit(205, "NtPulseEvent"); }
static void stub_206(void) { kstub_hit(206, "NtQueueApcThread"); }
static void stub_207(void) { kstub_hit(207, "NtQueryDirectoryFile"); }
static void stub_208(void) { kstub_hit(208, "NtQueryDirectoryObject"); }
static void stub_209(void) { kstub_hit(209, "NtQueryEvent"); }
static void stub_210(void) { kstub_hit(210, "NtQueryFullAttributesFile"); }
static void stub_211(void) { kstub_hit(211, "NtQueryInformationFile"); }
static void stub_212(void) { kstub_hit(212, "NtQueryIoCompletion"); }
static void stub_213(void) { kstub_hit(213, "NtQueryMutant"); }
static void stub_214(void) { kstub_hit(214, "NtQuerySemaphore"); }
static void stub_215(void) { kstub_hit(215, "NtQuerySymbolicLinkObject"); }
static void stub_216(void) { kstub_hit(216, "NtQueryTimer"); }
static void stub_217(void) { kstub_hit(217, "NtQueryVirtualMemory"); }
static void stub_218(void) { kstub_hit(218, "NtQueryVolumeInformationFile"); }
static void stub_219(void) { kstub_hit(219, "NtReadFile"); }
static void stub_220(void) { kstub_hit(220, "NtReadFileScatter"); }
static void stub_221(void) { kstub_hit(221, "NtReleaseMutant"); }
static void stub_222(void) { kstub_hit(222, "NtReleaseSemaphore"); }
static void stub_223(void) { kstub_hit(223, "NtRemoveIoCompletion"); }
static void stub_224(void) { kstub_hit(224, "NtResumeThread"); }
static void stub_225(void) { kstub_hit(225, "NtSetEvent"); }
static void stub_226(void) { kstub_hit(226, "NtSetInformationFile"); }
static void stub_227(void) { kstub_hit(227, "NtSetIoCompletion"); }
static void stub_228(void) { kstub_hit(228, "NtSetSystemTime"); }
static void stub_229(void) { kstub_hit(229, "NtSetTimerEx"); }
static void stub_230(void) { kstub_hit(230, "NtSignalAndWaitForSingleObjectEx"); }
static void stub_231(void) { kstub_hit(231, "NtSuspendThread"); }
static void stub_232(void) { kstub_hit(232, "NtUserIoApcDispatcher"); }
static void stub_233(void) { kstub_hit(233, "NtWaitForSingleObject"); }
static void stub_234(void) { kstub_hit(234, "NtWaitForSingleObjectEx"); }
static void stub_235(void) { kstub_hit(235, "NtWaitForMultipleObjectsEx"); }
static void stub_236(void) { kstub_hit(236, "NtWriteFile"); }
static void stub_237(void) { kstub_hit(237, "NtWriteFileGather"); }
static void stub_238(void) { kstub_hit(238, "NtYieldExecution"); }
static void stub_239(void) { kstub_hit(239, "ObCreateObject"); }
static void stub_240(void) { kstub_hit(240, "ObDirectoryObjectType"); }
static void stub_241(void) { kstub_hit(241, "ObInsertObject"); }
static void stub_242(void) { kstub_hit(242, "ObMakeTemporaryObject"); }
static void stub_243(void) { kstub_hit(243, "ObOpenObjectByName"); }
static void stub_244(void) { kstub_hit(244, "ObOpenObjectByPointer"); }
static void stub_245(void) { kstub_hit(245, "ObpObjectHandleTable"); }
static void stub_246(void) { kstub_hit(246, "ObReferenceObjectByHandle"); }
static void stub_247(void) { kstub_hit(247, "ObReferenceObjectByName"); }
static void stub_248(void) { kstub_hit(248, "ObReferenceObjectByPointer"); }
static void stub_249(void) { kstub_hit(249, "ObSymbolicLinkObjectType"); }
static void stub_250(void) { kstub_hit(250, "ObfDereferenceObject"); }
static void stub_251(void) { kstub_hit(251, "ObfReferenceObject"); }
static void stub_252(void) { kstub_hit(252, "PhyGetLinkState"); }
static void stub_253(void) { kstub_hit(253, "PhyInitialize"); }
static void stub_254(void) { kstub_hit(254, "PsCreateSystemThread"); }
static void stub_255(void) { kstub_hit(255, "PsCreateSystemThreadEx"); }
static void stub_256(void) { kstub_hit(256, "PsQueryStatistics"); }
static void stub_257(void) { kstub_hit(257, "PsSetCreateThreadNotifyRoutine"); }
static void stub_258(void) { kstub_hit(258, "PsTerminateSystemThread"); }
static void stub_259(void) { kstub_hit(259, "PsThreadObjectType"); }
static void stub_260(void) { kstub_hit(260, "RtlAnsiStringToUnicodeString"); }
static void stub_261(void) { kstub_hit(261, "RtlAppendStringToString"); }
static void stub_262(void) { kstub_hit(262, "RtlAppendUnicodeStringToString"); }
static void stub_263(void) { kstub_hit(263, "RtlAppendUnicodeToString"); }
static void stub_264(void) { kstub_hit(264, "RtlAssert"); }
static void stub_265(void) { kstub_hit(265, "RtlCaptureContext"); }
static void stub_266(void) { kstub_hit(266, "RtlCaptureStackBackTrace"); }
static void stub_267(void) { kstub_hit(267, "RtlCharToInteger"); }
static void stub_268(void) { kstub_hit(268, "RtlCompareMemory"); }
static void stub_269(void) { kstub_hit(269, "RtlCompareMemoryUlong"); }
static void stub_270(void) { kstub_hit(270, "RtlCompareString"); }
static void stub_271(void) { kstub_hit(271, "RtlCompareUnicodeString"); }
static void stub_272(void) { kstub_hit(272, "RtlCopyString"); }
static void stub_273(void) { kstub_hit(273, "RtlCopyUnicodeString"); }
static void stub_274(void) { kstub_hit(274, "RtlCreateUnicodeString"); }
static void stub_275(void) { kstub_hit(275, "RtlDowncaseUnicodeChar"); }
static void stub_276(void) { kstub_hit(276, "RtlDowncaseUnicodeString"); }
static void stub_277(void) { kstub_hit(277, "RtlEnterCriticalSection"); }
static void stub_278(void) { kstub_hit(278, "RtlEnterCriticalSectionAndRegion"); }
static void stub_279(void) { kstub_hit(279, "RtlEqualString"); }
static void stub_280(void) { kstub_hit(280, "RtlEqualUnicodeString"); }
static void stub_281(void) { kstub_hit(281, "RtlExtendedIntegerMultiply"); }
static void stub_282(void) { kstub_hit(282, "RtlExtendedLargeIntegerDivide"); }
static void stub_283(void) { kstub_hit(283, "RtlExtendedMagicDivide"); }
static void stub_284(void) { kstub_hit(284, "RtlFillMemory"); }
static void stub_285(void) { kstub_hit(285, "RtlFillMemoryUlong"); }
static void stub_286(void) { kstub_hit(286, "RtlFreeAnsiString"); }
static void stub_287(void) { kstub_hit(287, "RtlFreeUnicodeString"); }
static void stub_288(void) { kstub_hit(288, "RtlGetCallersAddress"); }
static void stub_289(void) { kstub_hit(289, "RtlInitAnsiString"); }
static void stub_290(void) { kstub_hit(290, "RtlInitUnicodeString"); }
static void stub_291(void) { kstub_hit(291, "RtlInitializeCriticalSection"); }
static void stub_292(void) { kstub_hit(292, "RtlIntegerToChar"); }
static void stub_293(void) { kstub_hit(293, "RtlIntegerToUnicodeString"); }
static void stub_294(void) { kstub_hit(294, "RtlLeaveCriticalSection"); }
static void stub_295(void) { kstub_hit(295, "RtlLeaveCriticalSectionAndRegion"); }
static void stub_296(void) { kstub_hit(296, "RtlLowerChar"); }
static void stub_297(void) { kstub_hit(297, "RtlMapGenericMask"); }
static void stub_298(void) { kstub_hit(298, "RtlMoveMemory"); }
static void stub_299(void) { kstub_hit(299, "RtlMultiByteToUnicodeN"); }
static void stub_300(void) { kstub_hit(300, "RtlMultiByteToUnicodeSize"); }
static void stub_301(void) { kstub_hit(301, "RtlNtStatusToDosError"); }
static void stub_302(void) { kstub_hit(302, "RtlRaiseException"); }
static void stub_303(void) { kstub_hit(303, "RtlRaiseStatus"); }
static void stub_304(void) { kstub_hit(304, "RtlTimeFieldsToTime"); }
static void stub_305(void) { kstub_hit(305, "RtlTimeToTimeFields"); }
static void stub_306(void) { kstub_hit(306, "RtlTryEnterCriticalSection"); }
static void stub_307(void) { kstub_hit(307, "RtlUlongByteSwap"); }
static void stub_308(void) { kstub_hit(308, "RtlUnicodeStringToAnsiString"); }
static void stub_309(void) { kstub_hit(309, "RtlUnicodeStringToInteger"); }
static void stub_310(void) { kstub_hit(310, "RtlUnicodeToMultiByteN"); }
static void stub_311(void) { kstub_hit(311, "RtlUnicodeToMultiByteSize"); }
static void stub_312(void) { kstub_hit(312, "RtlUnwind"); }
static void stub_313(void) { kstub_hit(313, "RtlUpcaseUnicodeChar"); }
static void stub_314(void) { kstub_hit(314, "RtlUpcaseUnicodeString"); }
static void stub_315(void) { kstub_hit(315, "RtlUpcaseUnicodeToMultiByteN"); }
static void stub_316(void) { kstub_hit(316, "RtlUpperChar"); }
static void stub_317(void) { kstub_hit(317, "RtlUpperString"); }
static void stub_318(void) { kstub_hit(318, "RtlUshortByteSwap"); }
static void stub_319(void) { kstub_hit(319, "RtlWalkFrameChain"); }
static void stub_320(void) { kstub_hit(320, "RtlZeroMemory"); }
static void stub_321(void) { kstub_hit(321, "XboxEEPROMKey"); }
static void stub_322(void) { kstub_hit(322, "XboxHardwareInfo"); }
static void stub_323(void) { kstub_hit(323, "XboxHDKey"); }
static void stub_324(void) { kstub_hit(324, "XboxKrnlVersion"); }
static void stub_325(void) { kstub_hit(325, "XboxSignatureKey"); }
static void stub_326(void) { kstub_hit(326, "XeImageFileName"); }
static void stub_327(void) { kstub_hit(327, "XeLoadSection"); }
static void stub_328(void) { kstub_hit(328, "XeUnloadSection"); }
static void stub_329(void) { kstub_hit(329, "READ_PORT_BUFFER_UCHAR"); }
static void stub_330(void) { kstub_hit(330, "READ_PORT_BUFFER_USHORT"); }
static void stub_331(void) { kstub_hit(331, "READ_PORT_BUFFER_ULONG"); }
static void stub_332(void) { kstub_hit(332, "WRITE_PORT_BUFFER_UCHAR"); }
static void stub_333(void) { kstub_hit(333, "WRITE_PORT_BUFFER_USHORT"); }
static void stub_334(void) { kstub_hit(334, "WRITE_PORT_BUFFER_ULONG"); }
static void stub_335(void) { kstub_hit(335, "XcSHAInit"); }
static void stub_336(void) { kstub_hit(336, "XcSHAUpdate"); }
static void stub_337(void) { kstub_hit(337, "XcSHAFinal"); }
static void stub_338(void) { kstub_hit(338, "XcRC4Key"); }
static void stub_339(void) { kstub_hit(339, "XcRC4Crypt"); }
static void stub_340(void) { kstub_hit(340, "XcHMAC"); }
static void stub_341(void) { kstub_hit(341, "XcPKEncPublic"); }
static void stub_342(void) { kstub_hit(342, "XcPKDecPrivate"); }
static void stub_343(void) { kstub_hit(343, "XcPKGetKeyLen"); }
static void stub_344(void) { kstub_hit(344, "XcVerifyPKCS1Signature"); }
static void stub_345(void) { kstub_hit(345, "XcModExp"); }
static void stub_346(void) { kstub_hit(346, "XcDESKeyParity"); }
static void stub_347(void) { kstub_hit(347, "XcKeyTable"); }
static void stub_348(void) { kstub_hit(348, "XcBlockCrypt"); }
static void stub_349(void) { kstub_hit(349, "XcBlockCryptCBC"); }
static void stub_350(void) { kstub_hit(350, "XcCryptService"); }
static void stub_351(void) { kstub_hit(351, "XcUpdateCrypto"); }
static void stub_352(void) { kstub_hit(352, "RtlRip"); }
static void stub_353(void) { kstub_hit(353, "XboxLANKey"); }
static void stub_354(void) { kstub_hit(354, "XboxAlternateSignatureKeys"); }
static void stub_355(void) { kstub_hit(355, "XePublicKeyData"); }
static void stub_356(void) { kstub_hit(356, "HalBootSMCVideoMode"); }
static void stub_357(void) { kstub_hit(357, "IdexChannelObject"); }
static void stub_358(void) { kstub_hit(358, "HalIsResetOrShutdownPending"); }
static void stub_359(void) { kstub_hit(359, "IoMarkIrpMustComplete"); }
static void stub_360(void) { kstub_hit(360, "HalInitiateShutdown"); }
static void stub_361(void) { kstub_hit(361, "RtlSnprintf"); }
static void stub_362(void) { kstub_hit(362, "RtlSprintf"); }
static void stub_363(void) { kstub_hit(363, "RtlVsnprintf"); }
static void stub_364(void) { kstub_hit(364, "RtlVsprintf"); }
static void stub_365(void) { kstub_hit(365, "HalEnableSecureTrayEject"); }
static void stub_366(void) { kstub_hit(366, "HalWriteSMCScratchRegister"); }
static void stub_367(void) { kstub_hit(367, "UNEXPORTED_ORDINAL_367"); }
static void stub_368(void) { kstub_hit(368, "UNEXPORTED_ORDINAL_368"); }
static void stub_369(void) { kstub_hit(369, "UNEXPORTED_ORDINAL_369"); }
static void stub_370(void) { kstub_hit(370, "UNEXPORTED_ORDINAL_370"); }
static void stub_371(void) { kstub_hit(371, "UNEXPORTED_ORDINAL_371"); }
static void stub_372(void) { kstub_hit(372, "UNEXPORTED_ORDINAL_372"); }
static void stub_373(void) { kstub_hit(373, "UNEXPORTED_ORDINAL_373"); }
static void stub_374(void) { kstub_hit(374, "MmDbgAllocateMemory"); }
static void stub_375(void) { kstub_hit(375, "MmDbgFreeMemory"); }
static void stub_376(void) { kstub_hit(376, "MmDbgQueryAvailablePages"); }
static void stub_377(void) { kstub_hit(377, "MmDbgReleaseAddress"); }
static void stub_378(void) { kstub_hit(378, "MmDbgWriteCheck"); }

typedef void (*kstub_fn)(void);
static kstub_fn const KSTUB_TABLE[379] = {
    [1] = stub_1,
    [2] = stub_2,
    [3] = stub_3,
    [4] = stub_4,
    [5] = stub_5,
    [6] = stub_6,
    [7] = stub_7,
    [8] = stub_8,
    [9] = stub_9,
    [10] = stub_10,
    [11] = stub_11,
    [12] = stub_12,
    [13] = stub_13,
    [14] = stub_14,
    [15] = stub_15,
    [16] = stub_16,
    [17] = stub_17,
    [18] = stub_18,
    [19] = stub_19,
    [20] = stub_20,
    [21] = stub_21,
    [22] = stub_22,
    [23] = stub_23,
    [24] = stub_24,
    [25] = stub_25,
    [26] = stub_26,
    [27] = stub_27,
    [28] = stub_28,
    [29] = stub_29,
    [30] = stub_30,
    [31] = stub_31,
    [32] = stub_32,
    [33] = stub_33,
    [34] = stub_34,
    [35] = stub_35,
    [36] = stub_36,
    [37] = stub_37,
    [38] = stub_38,
    [39] = stub_39,
    [40] = stub_40,
    [41] = stub_41,
    [42] = stub_42,
    [43] = stub_43,
    [44] = stub_44,
    [45] = stub_45,
    [46] = stub_46,
    [47] = stub_47,
    [48] = stub_48,
    [49] = stub_49,
    [50] = stub_50,
    [51] = stub_51,
    [52] = stub_52,
    [53] = stub_53,
    [54] = stub_54,
    [55] = stub_55,
    [56] = stub_56,
    [57] = stub_57,
    [58] = stub_58,
    [59] = stub_59,
    [60] = stub_60,
    [61] = stub_61,
    [62] = stub_62,
    [63] = stub_63,
    [64] = stub_64,
    [65] = stub_65,
    [66] = stub_66,
    [67] = stub_67,
    [68] = stub_68,
    [69] = stub_69,
    [70] = stub_70,
    [71] = stub_71,
    [72] = stub_72,
    [73] = stub_73,
    [74] = stub_74,
    [75] = stub_75,
    [76] = stub_76,
    [77] = stub_77,
    [78] = stub_78,
    [79] = stub_79,
    [80] = stub_80,
    [81] = stub_81,
    [82] = stub_82,
    [83] = stub_83,
    [84] = stub_84,
    [85] = stub_85,
    [86] = stub_86,
    [87] = stub_87,
    [88] = stub_88,
    [89] = stub_89,
    [90] = stub_90,
    [91] = stub_91,
    [92] = stub_92,
    [93] = stub_93,
    [94] = stub_94,
    [95] = stub_95,
    [96] = stub_96,
    [97] = stub_97,
    [98] = stub_98,
    [99] = stub_99,
    [100] = stub_100,
    [101] = stub_101,
    [102] = stub_102,
    [103] = stub_103,
    [104] = stub_104,
    [105] = stub_105,
    [106] = stub_106,
    [107] = stub_107,
    [108] = stub_108,
    [109] = stub_109,
    [110] = stub_110,
    [111] = stub_111,
    [112] = stub_112,
    [113] = stub_113,
    [114] = stub_114,
    [115] = stub_115,
    [116] = stub_116,
    [117] = stub_117,
    [118] = stub_118,
    [119] = stub_119,
    [120] = stub_120,
    [121] = stub_121,
    [122] = stub_122,
    [123] = stub_123,
    [124] = stub_124,
    [125] = stub_125,
    [126] = stub_126,
    [127] = stub_127,
    [128] = stub_128,
    [129] = stub_129,
    [130] = stub_130,
    [131] = stub_131,
    [132] = stub_132,
    [133] = stub_133,
    [134] = stub_134,
    [135] = stub_135,
    [136] = stub_136,
    [137] = stub_137,
    [138] = stub_138,
    [139] = stub_139,
    [140] = stub_140,
    [141] = stub_141,
    [142] = stub_142,
    [143] = stub_143,
    [144] = stub_144,
    [145] = stub_145,
    [146] = stub_146,
    [147] = stub_147,
    [148] = stub_148,
    [149] = stub_149,
    [150] = stub_150,
    [151] = stub_151,
    [152] = stub_152,
    [153] = stub_153,
    [154] = stub_154,
    [155] = stub_155,
    [156] = stub_156,
    [157] = stub_157,
    [158] = stub_158,
    [159] = stub_159,
    [160] = stub_160,
    [161] = stub_161,
    [162] = stub_162,
    [163] = stub_163,
    [164] = stub_164,
    [165] = stub_165,
    [166] = stub_166,
    [167] = stub_167,
    [168] = stub_168,
    [169] = stub_169,
    [170] = stub_170,
    [171] = stub_171,
    [172] = stub_172,
    [173] = stub_173,
    [174] = stub_174,
    [175] = stub_175,
    [176] = stub_176,
    [177] = stub_177,
    [178] = stub_178,
    [179] = stub_179,
    [180] = stub_180,
    [181] = stub_181,
    [182] = stub_182,
    [183] = stub_183,
    [184] = stub_184,
    [185] = stub_185,
    [186] = stub_186,
    [187] = stub_187,
    [188] = stub_188,
    [189] = stub_189,
    [190] = stub_190,
    [191] = stub_191,
    [192] = stub_192,
    [193] = stub_193,
    [194] = stub_194,
    [195] = stub_195,
    [196] = stub_196,
    [197] = stub_197,
    [198] = stub_198,
    [199] = stub_199,
    [200] = stub_200,
    [201] = stub_201,
    [202] = stub_202,
    [203] = stub_203,
    [204] = stub_204,
    [205] = stub_205,
    [206] = stub_206,
    [207] = stub_207,
    [208] = stub_208,
    [209] = stub_209,
    [210] = stub_210,
    [211] = stub_211,
    [212] = stub_212,
    [213] = stub_213,
    [214] = stub_214,
    [215] = stub_215,
    [216] = stub_216,
    [217] = stub_217,
    [218] = stub_218,
    [219] = stub_219,
    [220] = stub_220,
    [221] = stub_221,
    [222] = stub_222,
    [223] = stub_223,
    [224] = stub_224,
    [225] = stub_225,
    [226] = stub_226,
    [227] = stub_227,
    [228] = stub_228,
    [229] = stub_229,
    [230] = stub_230,
    [231] = stub_231,
    [232] = stub_232,
    [233] = stub_233,
    [234] = stub_234,
    [235] = stub_235,
    [236] = stub_236,
    [237] = stub_237,
    [238] = stub_238,
    [239] = stub_239,
    [240] = stub_240,
    [241] = stub_241,
    [242] = stub_242,
    [243] = stub_243,
    [244] = stub_244,
    [245] = stub_245,
    [246] = stub_246,
    [247] = stub_247,
    [248] = stub_248,
    [249] = stub_249,
    [250] = stub_250,
    [251] = stub_251,
    [252] = stub_252,
    [253] = stub_253,
    [254] = stub_254,
    [255] = stub_255,
    [256] = stub_256,
    [257] = stub_257,
    [258] = stub_258,
    [259] = stub_259,
    [260] = stub_260,
    [261] = stub_261,
    [262] = stub_262,
    [263] = stub_263,
    [264] = stub_264,
    [265] = stub_265,
    [266] = stub_266,
    [267] = stub_267,
    [268] = stub_268,
    [269] = stub_269,
    [270] = stub_270,
    [271] = stub_271,
    [272] = stub_272,
    [273] = stub_273,
    [274] = stub_274,
    [275] = stub_275,
    [276] = stub_276,
    [277] = stub_277,
    [278] = stub_278,
    [279] = stub_279,
    [280] = stub_280,
    [281] = stub_281,
    [282] = stub_282,
    [283] = stub_283,
    [284] = stub_284,
    [285] = stub_285,
    [286] = stub_286,
    [287] = stub_287,
    [288] = stub_288,
    [289] = stub_289,
    [290] = stub_290,
    [291] = stub_291,
    [292] = stub_292,
    [293] = stub_293,
    [294] = stub_294,
    [295] = stub_295,
    [296] = stub_296,
    [297] = stub_297,
    [298] = stub_298,
    [299] = stub_299,
    [300] = stub_300,
    [301] = stub_301,
    [302] = stub_302,
    [303] = stub_303,
    [304] = stub_304,
    [305] = stub_305,
    [306] = stub_306,
    [307] = stub_307,
    [308] = stub_308,
    [309] = stub_309,
    [310] = stub_310,
    [311] = stub_311,
    [312] = stub_312,
    [313] = stub_313,
    [314] = stub_314,
    [315] = stub_315,
    [316] = stub_316,
    [317] = stub_317,
    [318] = stub_318,
    [319] = stub_319,
    [320] = stub_320,
    [321] = stub_321,
    [322] = stub_322,
    [323] = stub_323,
    [324] = stub_324,
    [325] = stub_325,
    [326] = stub_326,
    [327] = stub_327,
    [328] = stub_328,
    [329] = stub_329,
    [330] = stub_330,
    [331] = stub_331,
    [332] = stub_332,
    [333] = stub_333,
    [334] = stub_334,
    [335] = stub_335,
    [336] = stub_336,
    [337] = stub_337,
    [338] = stub_338,
    [339] = stub_339,
    [340] = stub_340,
    [341] = stub_341,
    [342] = stub_342,
    [343] = stub_343,
    [344] = stub_344,
    [345] = stub_345,
    [346] = stub_346,
    [347] = stub_347,
    [348] = stub_348,
    [349] = stub_349,
    [350] = stub_350,
    [351] = stub_351,
    [352] = stub_352,
    [353] = stub_353,
    [354] = stub_354,
    [355] = stub_355,
    [356] = stub_356,
    [357] = stub_357,
    [358] = stub_358,
    [359] = stub_359,
    [360] = stub_360,
    [361] = stub_361,
    [362] = stub_362,
    [363] = stub_363,
    [364] = stub_364,
    [365] = stub_365,
    [366] = stub_366,
    [367] = stub_367,
    [368] = stub_368,
    [369] = stub_369,
    [370] = stub_370,
    [371] = stub_371,
    [372] = stub_372,
    [373] = stub_373,
    [374] = stub_374,
    [375] = stub_375,
    [376] = stub_376,
    [377] = stub_377,
    [378] = stub_378,
};
#define KSTUB_MAX 378

#endif
