/* كتالوج الوحدات والباقات — مصدر واحد للحقيقة على السيرفر (ونسخة مطابقة في التطبيق: license.js).
   الترخيص الموقّع يحمل قائمة الوحدات المسموحة صراحةً، فالتطبيق لا يعتمد على الكتالوج للتحقق، بل للعرض فقط. */
const MODULES = {
  employees: { title: 'الموظفون', core: true },
  documents: { title: 'المستندات وتنبيهات الانتهاء' },
  leaves: { title: 'الإجازات ونهاية الخدمة' },
  letters: { title: 'الخطابات والنماذج' },
  guide: { title: 'دليل الإجراءات' },
  payroll: { title: 'الرواتب' },
  offers: { title: 'عروض العمل' },
  reports: { title: 'التقارير والتحليلات' },
  finance: { title: 'المالية والخزنة' },
  field: { title: 'الميدان والحضور' },
  taxes: { title: 'الضرائب' }
};
const PLANS = {
  starter: { title: 'الأساسية', modules: ['employees', 'documents', 'leaves', 'letters', 'guide'] },
  pro: { title: 'الاحترافية', modules: ['employees', 'documents', 'leaves', 'letters', 'guide', 'payroll', 'offers', 'reports'] },
  business: { title: 'الكاملة', modules: Object.keys(MODULES) }
};
/* يرجّع قائمة وحدات نظيفة: من الباقة أو من قائمة مخصّصة، مع إجبار الوحدات الأساسية */
function resolveModules(plan, custom) {
  let list;
  if (Array.isArray(custom) && custom.length) list = custom; else if (PLANS[plan]) list = PLANS[plan].modules; else return null;
  const set = new Set(list.filter(m => MODULES[m]));
  for (const k of Object.keys(MODULES)) if (MODULES[k].core) set.add(k);
  return Object.keys(MODULES).filter(k => set.has(k));
}
module.exports = { MODULES, PLANS, resolveModules };
