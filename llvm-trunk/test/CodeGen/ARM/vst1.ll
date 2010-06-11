; RUN: llc < %s -march=arm -mattr=+neon | FileCheck %s

define void @vst1i8(i8* %A, <8 x i8>* %B) nounwind {
;CHECK: vst1i8:
;CHECK: vst1.8
	%tmp1 = load <8 x i8>* %B
	call void @llvm.arm.neon.vst1.v8i8(i8* %A, <8 x i8> %tmp1)
	ret void
}

define void @vst1i16(i16* %A, <4 x i16>* %B) nounwind {
;CHECK: vst1i16:
;CHECK: vst1.16
	%tmp1 = load <4 x i16>* %B
	call void @llvm.arm.neon.vst1.v4i16(i16* %A, <4 x i16> %tmp1)
	ret void
}

define void @vst1i32(i32* %A, <2 x i32>* %B) nounwind {
;CHECK: vst1i32:
;CHECK: vst1.32
	%tmp1 = load <2 x i32>* %B
	call void @llvm.arm.neon.vst1.v2i32(i32* %A, <2 x i32> %tmp1)
	ret void
}

define void @vst1f(float* %A, <2 x float>* %B) nounwind {
;CHECK: vst1f:
;CHECK: vst1.32
	%tmp1 = load <2 x float>* %B
	call void @llvm.arm.neon.vst1.v2f32(float* %A, <2 x float> %tmp1)
	ret void
}

define void @vst1i64(i64* %A, <1 x i64>* %B) nounwind {
;CHECK: vst1i64:
;CHECK: vst1.64
	%tmp1 = load <1 x i64>* %B
	call void @llvm.arm.neon.vst1.v1i64(i64* %A, <1 x i64> %tmp1)
	ret void
}

define void @vst1Qi8(i8* %A, <16 x i8>* %B) nounwind {
;CHECK: vst1Qi8:
;CHECK: vst1.8
	%tmp1 = load <16 x i8>* %B
	call void @llvm.arm.neon.vst1.v16i8(i8* %A, <16 x i8> %tmp1)
	ret void
}

define void @vst1Qi16(i16* %A, <8 x i16>* %B) nounwind {
;CHECK: vst1Qi16:
;CHECK: vst1.16
	%tmp1 = load <8 x i16>* %B
	call void @llvm.arm.neon.vst1.v8i16(i16* %A, <8 x i16> %tmp1)
	ret void
}

define void @vst1Qi32(i32* %A, <4 x i32>* %B) nounwind {
;CHECK: vst1Qi32:
;CHECK: vst1.32
	%tmp1 = load <4 x i32>* %B
	call void @llvm.arm.neon.vst1.v4i32(i32* %A, <4 x i32> %tmp1)
	ret void
}

define void @vst1Qf(float* %A, <4 x float>* %B) nounwind {
;CHECK: vst1Qf:
;CHECK: vst1.32
	%tmp1 = load <4 x float>* %B
	call void @llvm.arm.neon.vst1.v4f32(float* %A, <4 x float> %tmp1)
	ret void
}

define void @vst1Qi64(i64* %A, <2 x i64>* %B) nounwind {
;CHECK: vst1Qi64:
;CHECK: vst1.64
	%tmp1 = load <2 x i64>* %B
	call void @llvm.arm.neon.vst1.v2i64(i64* %A, <2 x i64> %tmp1)
	ret void
}

declare void @llvm.arm.neon.vst1.v8i8(i8*, <8 x i8>) nounwind
declare void @llvm.arm.neon.vst1.v4i16(i8*, <4 x i16>) nounwind
declare void @llvm.arm.neon.vst1.v2i32(i8*, <2 x i32>) nounwind
declare void @llvm.arm.neon.vst1.v2f32(i8*, <2 x float>) nounwind
declare void @llvm.arm.neon.vst1.v1i64(i8*, <1 x i64>) nounwind

declare void @llvm.arm.neon.vst1.v16i8(i8*, <16 x i8>) nounwind
declare void @llvm.arm.neon.vst1.v8i16(i8*, <8 x i16>) nounwind
declare void @llvm.arm.neon.vst1.v4i32(i8*, <4 x i32>) nounwind
declare void @llvm.arm.neon.vst1.v4f32(i8*, <4 x float>) nounwind
declare void @llvm.arm.neon.vst1.v2i64(i8*, <2 x i64>) nounwind
