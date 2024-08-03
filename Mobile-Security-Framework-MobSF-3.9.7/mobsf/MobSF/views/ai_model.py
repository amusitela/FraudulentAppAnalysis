import json
from django.http import JsonResponse
from django.core.files.storage import default_storage
import numpy as np
import joblib
from androguard.misc import AnalyzeAPK
from django.conf import settings
import os
from decouple import config
import os
import base64
import requests
from PIL import Image

model_filename = settings.MODEL_FILENAME
vectorizer_filename = settings.VECTORIZER_FILENAME

clf = joblib.load(model_filename)
vectorizer = joblib.load(vectorizer_filename)

K = 500
api_key = config('APIKEY')
screen = config('SCREEN')


def extract_function_signature(apk_path):
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        function_signature = []
        for meth_analysis in dx.get_methods():
            if meth_analysis.is_external():
                continue
            if len(meth_analysis.get_xref_to()) == 0:
                continue
            api_list = []
            for _, call, _ in meth_analysis.get_xref_to():
                if call.is_external():
                    api_list.append(call.name)
            if api_list:
                function_signature.append(" ".join(api_list))
        return " ".join(function_signature)
    except Exception as e:
        print(f"Error analyzing {apk_path}: {e}")
        return ""


def analyze_apk(file_path):
    new_app_function_signature = extract_function_signature(file_path)
    if new_app_function_signature:
        new_app_tfidf = vectorizer.transform([new_app_function_signature]).toarray()
        # 选取新的应用程序中 TF-IDF 值最高的 K 个特征
        top_k_new_app_indices = np.argsort(new_app_tfidf, axis=1)[:, -K:]
        new_app_tfidf_top_k = np.zeros((1, K))
        new_app_tfidf_top_k[0] = new_app_tfidf[0, top_k_new_app_indices[0]]
        new_app_probabilities = clf.predict_proba(new_app_tfidf_top_k)

        # 获取类别标签
        class_labels = clf.classes_

        # 创建一个数组来存储类别和置信度
        results = []
        for label, prob in zip(class_labels, new_app_probabilities[0]):
            results.append({"类别": label, "置信度": prob})

        # 按照置信度进行降序排序
        sorted_results = sorted(results, key=lambda x: x["置信度"], reverse=True)
        result_str = "@".join([f"{result['类别']}${result['置信度']:.2f}" for result in sorted_results])
        return result_str
    else:
        return "无法提取函数签名"


def encode_image(image_path):
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode('utf-8')


# def chatGPT(directory_paths):
#     content = [
#         {
#             "type": "text",
#             "text": "请根据截图识别app的类别，只能选涉黄涉诈还是涉赌，直接告诉我最可能的结果，不要说其他话"
#             # "text": "请根据截图识别违法app的类别，只能选涉黄涉诈还是涉赌，告诉我每个类别的置信度，不要说其他话"
#         }
#     ]
#
#     for directory_path in directory_paths:
#         base64_image = encode_image(directory_path)
#         content.append({
#             "type": "image_url",
#             "image_url": f"data:image/jpeg;base64,{base64_image}"
#         })
#
#     headers = {
#         "Content-Type": "application/json",
#         "Authorization": f"Bearer {api_key}"
#     }
#
#     payload = {
#         "model": "gpt-4-v",
#         "messages": [
#             {
#                 "role": "user",
#                 "content": content
#             }
#         ],
#         "max_tokens": 300
#     }
#
#     response = requests.post("https://api1.zhtec.xyz/v1/chat/completions", headers=headers, json=payload)
#     for line in response.iter_lines():
#         if line:
#             decoded_line = line.decode('utf-8')
#             response_data = json.loads(decoded_line)
#             # 提取分类结果
#             result = response_data['choices'][0]['message']['content']
#             return result


def chatGPT(largest_png_path):
    # Getting the base64 string of the largest PNG image
    base64_image = encode_image(largest_png_path)

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "说中文，请根据截图识别违法app的类别，只能选涉黄涉诈还是涉赌，告诉我每个类别的置信度和理由，格式像这样：类别:涉诈$置信度:高$理由:..@类别:涉黄$置信度:低$理由:..@类别:涉赌$置信度:低$理由:..，不要说其他话"
                    },
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/jpeg;base64,{base64_image}"
                        }
                    }
                ]
            }
        ],
    }

    response = requests.post("https://api1.zhtec.xyz/v1/chat/completions", headers=headers, json=payload)
    for line in response.iter_lines():
        if line:
            decoded_line = line.decode('utf-8')
            response_data = json.loads(decoded_line)
            # 提取分类结果
            result = response_data['choices'][0]['message']['content']
            return result


def combine_images(images, orientation='horizontal'):
    """
    将多张图片合并成一张图片。

    :param images: 图片路径列表
    :param orientation: 合并方向，'horizontal' 或 'vertical'
    :return: 合并后的图片
    """
    # 打开所有图片
    imgs = [Image.open(img) for img in images]

    if orientation == 'horizontal':
        # 计算合并后的图片宽度和高度
        total_width = sum(img.width for img in imgs)
        max_height = max(img.height for img in imgs)

        # 创建合并后的图片
        new_img = Image.new('RGB', (total_width, max_height))

        # 拼接图片
        x_offset = 0
        for img in imgs:
            new_img.paste(img, (x_offset, 0))
            x_offset += img.width

    elif orientation == 'vertical':
        # 计算合并后的图片宽度和高度
        max_width = max(img.width for img in imgs)
        total_height = sum(img.height for img in imgs)

        # 创建合并后的图片
        new_img = Image.new('RGB', (max_width, total_height))

        # 拼接图片
        y_offset = 0
        for img in imgs:
            new_img.paste(img, (0, y_offset))
            y_offset += img.height

    else:
        raise ValueError("Orientation must be 'horizontal' or 'vertical'")
    save_path = f'{screen}/combined_image.png'
    new_img.save(save_path)
    return save_path
