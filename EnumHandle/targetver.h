#pragma once

// SDKDDKVer.h をインクルードすると、利用できる最も上位の Windows プラットフォームが定義されます。

// 以前の Windows プラットフォーム用にアプリケーションをビルドする場合は、WinSDKVer.h をインクルードし、
// SDKDDKVer.h をインクルードする前に、サポート対象とするプラットフォームを示すように _WIN32_WINNT マクロを設定します。

#include <winsdkver.h>

#define _WIN32_WINNT _WIN32_WINNT_WIN7
#define WINVER       _WIN32_WINNT_WIN7


#include <SDKDDKVer.h>
