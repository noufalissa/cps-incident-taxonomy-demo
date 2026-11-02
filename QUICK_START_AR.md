# التشغيل السريع لبكرا

## الخيار الأسهل: GitHub + Streamlit Cloud

1. فك ضغط الملف `cps_taxonomy_demo.zip`.
2. ادخل إلى GitHub وأنشئ Repository جديدًا، مثل:
   `cps-incident-taxonomy-demo`
3. اختر **Add file → Upload files**.
4. ارفع **محتويات المجلد نفسها**، وليس ملف ZIP فقط.
5. تأكد أن `app.py` و`requirements.txt` موجودان في الصفحة الرئيسية للـRepository.
6. افتح Streamlit Community Cloud وسجّل الدخول باستخدام GitHub.
7. اختر **Create app** ثم:
   - Repository: المستودع الذي أنشأته
   - Branch: `main`
   - Main file path: `app.py`
8. اضغط **Deploy**.
9. بعد التشغيل ستحصل على رابط عام ينتهي بـ:
   `.streamlit.app`

## داخل العرض

1. اختر `Bundled five incidents`.
2. اختر حادثة من القائمة.
3. اترك `Fetch and analyze source URLs` مفعّلًا.
4. اضغط `Retrieve evidence and classify`.
5. اعرض:
   - Classification summary
   - Evidence clauses
   - Retrieval log

## إذا فشل جلب أحد المواقع

هذا طبيعي؛ بعض المواقع تمنع الاستخراج الآلي. البرنامج سيستمر باستخدام
`Verified Impact Summary` الموجودة في ملف البيانات، لذلك ستبقى التجربة قابلة للعرض.

## تفسير النتائج

- `CONFIRMED`: ندخله ضمن تصنيف الورقة.
- `CLAIMED`: ادعاء غير مؤكد.
- `POTENTIAL`: أثر محتمل لم يقع فعليًا.
- `UNAFFECTED`: المصدر ذكر صراحة أن النظام أو الخاصية لم تتأثر.

لا تعدّل القواعد قبل اجتماع الغد إلا إذا ظهر خطأ واضح؛ استخدم التجربة كمثال أولي
على الفكرة، وليس كنظام نهائي مُقيّم علميًا.
