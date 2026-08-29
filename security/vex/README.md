# Правила VEX и временных waiver

Этот каталог содержит только CycloneDX 1.6 VEX со статусом `not_affected`.
VEX означает: уязвимый пакет найден в конкретном образе, но технический разбор
доказал, что именно этот образ не затронут. Реальная, но временно принимаемая
уязвимость записывается отдельно в `security/waivers.json` и VEX не называется.

Grype 0.117.0 принимает OpenVEX и CSAF VEX, но не CycloneDX VEX. Поэтому
`scripts/evaluate_image_scan.py` применяет выбранный проектом CycloneDX-профиль
к сырому JSON Grype. Ошибка Grype, повреждённый отчёт или неверная политика
всегда блокируют job и никаким VEX/waiver не подавляются.

## Когда разрешён VEX

Для каждого утверждения обязательны:

- точные CVE, package name, version, purl и immutable image digest;
- только `analysis.state: not_affected` и конкретный CycloneDX justification;
- подробный `analysis.detail` с описанием проверенного exploit path;
- один или несколько стабильных HTTPS evidence URL: upstream advisory,
  permalink на исходник/конфигурацию или тест, подтверждающий вывод;
- `reviewed-by`, `reviewed-at` и ссылка на PR, в котором принято решение.

Одной фразы «ложное срабатывание», отсутствия публичного exploit или низкого
EPSS недостаточно. `in_triage`, `exploitable`, wildcard и ссылка только на сам
отчёт сканера ничего не подавляют. Один statement относится ровно к одному
пакету; это намеренно не даёт спрятать несколько совпадений общей формулировкой.

Файл называется `<64 hex digest>.cdx.json`. Минимальный профиль:

```json
{
  "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:11111111-1111-4111-8111-111111111111",
  "version": 1,
  "metadata": {
    "timestamp": "2026-08-29T12:00:00Z",
    "component": {
      "bom-ref": "pkg:oci/insights-api@sha256:<64 hex digest>",
      "type": "container",
      "name": "insights-api",
      "version": "sha256:<64 hex digest>"
    },
    "properties": [
      {"name": "smart-lists:vex:reviewed-by", "value": "@github-login"},
      {"name": "smart-lists:vex:reviewed-at", "value": "2026-08-29T12:00:00Z"},
      {"name": "smart-lists:vex:approval", "value": "https://github.com/kzhirikhin/smart-lists-fastapi-service/pull/123"}
    ]
  },
  "components": [
    {
      "bom-ref": "pkg:deb/debian/package@1.2.3?arch=amd64&distro=debian-13",
      "type": "library",
      "name": "package",
      "version": "1.2.3",
      "purl": "pkg:deb/debian/package@1.2.3?arch=amd64&distro=debian-13"
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2026-12345",
      "analysis": {
        "state": "not_affected",
        "justification": "code_not_reachable",
        "detail": "Не менее 80 символов: какой уязвимый путь проверен и почему он недостижим именно в этом образе."
      },
      "affects": [
        {"ref": "pkg:deb/debian/package@1.2.3?arch=amd64&distro=debian-13"}
      ],
      "properties": [
        {"name": "smart-lists:vex:evidence", "value": "https://github.com/owner/repository/blob/commit/test"}
      ]
    }
  ]
}
```

## Когда разрешён waiver

Waiver фиксирует не «не затронуто», а осознанное временное принятие реального
риска. Запись обязана иметь точную привязку, содержательную причину, план
исправления, owner, явного approver, PR approval, evidence и срок не более 30
дней. После `expiresAt` она автоматически перестаёт подавлять находку. Продление
делается новой записью с новым ID и новым review; менять старую дату на месте
нельзя. Один владелец проекта может быть и owner, и approver, но все поля и PR
всё равно обязательны: решение остаётся видимым и намеренным.

Форма одной записи в `security/waivers.json`:

```json
{
  "id": "WAIVER-2026-001",
  "vulnerabilityId": "CVE-2026-12345",
  "imageDigest": "sha256:<64 hex digest>",
  "package": {
    "name": "package",
    "version": "1.2.3",
    "purl": "pkg:deb/debian/package@1.2.3?arch=amd64&distro=debian-13"
  },
  "reason": "Не менее 80 символов: почему риск приходится принять сейчас и как ограничен возможный ущерб.",
  "remediationPlan": "Не менее 40 символов: конкретное исправление и условие его выполнения.",
  "owner": "@github-login",
  "approvedBy": "@github-login",
  "approval": "https://github.com/kzhirikhin/smart-lists-fastapi-service/pull/123",
  "evidence": ["https://security-tracker.example/CVE-2026-12345"],
  "approvedAt": "2026-08-29T12:00:00Z",
  "expiresAt": "2026-09-12T12:00:00Z"
}
```

Пустые списки VEX и waiver являются нормальным безопасным состоянием. На
2026-08-29 ни одной текущей CVE исключение не выдано.
