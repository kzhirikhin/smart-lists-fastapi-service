"""Статические контракты цепочки поставок.

Проверки читают файлы репозитория и падают на нарушении. Смысл именно в форме:
все три утверждения ниже сегодня истинны, и защищать надо не их появление, а то,
что они не станут ложными молча. Разница между «сегодня верно» и «не может стать
неверным» — это наличие проверки.

Аналог в основном репозитории — набор `security-static`. Здесь отдельного gate
нет, поэтому контракты живут в обычном прогоне pytest, который уже является
required check.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

# Значение `uses:` вместе с остатком строки: комментарий версии проверяется той
# же проверкой, что и сам пин.
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)(.*)$", re.MULTILINE)

# Строка `name==version` в начале записи pip-compile.
PINNED = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\]+)", re.MULTILINE)


def _workflows() -> list[tuple[str, str]]:
    return sorted(
        (path.name, path.read_text(encoding="utf-8"))
        for path in WORKFLOWS_DIR.iterdir()
        if path.suffix in {".yml", ".yaml"}
    )


def _action_refs() -> list[tuple[str, str, str]]:
    refs: list[tuple[str, str, str]] = []
    for name, body in _workflows():
        for match in USES.finditer(body):
            refs.append((name, match.group(1), match.group(2)))
    return refs


def _pins(filename: str) -> dict[str, str]:
    body = (REPO_ROOT / filename).read_text(encoding="utf-8")
    # Комментарии отбрасываются: `# via fastapi` под каждой записью и заголовок
    # pip-compile не должны попадать в разбор.
    payload = "\n".join(
        line for line in body.splitlines() if not line.lstrip().startswith("#")
    )
    return {
        name.lower().replace("_", "-"): version
        for name, version in PINNED.findall(payload)
    }


class TestActionPins:
    """Actions закреплены по SHA.

    Тег в реестре — это имя, которое владелец может переставить на другое
    содержимое в любой момент: `@v7` завтра означает не то, что сегодня, и в
    диффе не будет ни строки. Скомпрометированный action исполняется с правами
    workflow, а в `deploy.yml` — рядом с OIDC-токеном на Cloud Run.
    """

    def test_workflows_are_visible(self) -> None:
        # Проверки ниже проходят и на пустом списке, поэтому сначала требуем,
        # чтобы разбор действительно что-то нашёл.
        names = [name for name, _ in _workflows()]
        assert "ci.yml" in names
        assert "deploy.yml" in names
        assert len(_action_refs()) >= 5

    @pytest.mark.parametrize(("workflow", "ref", "rest"), _action_refs())
    def test_pinned_by_full_sha(self, workflow: str, ref: str, rest: str) -> None:
        if ref.startswith("./") or ref.startswith("../"):
            # Локальное действие приезжает тем же checkout, что и код;
            # подменить его переносом тега нельзя.
            return
        # Ровно 40 hex после `@`: `@v7`, `@main` и укороченный SHA не проходят.
        assert re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", ref), f"{workflow}: {ref}"

    @pytest.mark.parametrize(("workflow", "ref", "rest"), _action_refs())
    def test_version_comment_present(self, workflow: str, ref: str, rest: str) -> None:
        if ref.startswith("./") or ref.startswith("../"):
            return
        # Без комментария человек не может прочитать закреплённую версию, не
        # сходив в реестр. Dependabot двигает пин вместе с комментарием.
        assert re.search(r"#\s*v?\d", rest), f"{workflow}: {ref}"


class TestRequirementsDrift:
    """`requirements.txt` не расходится с `requirements.in`.

    Полные наборы разворачивает pip-compile, но pip читает только `.txt`.
    Поэтому ручная правка `.txt` — например, чтобы поднять одну версию, не
    поднимая контейнер, — делает `.in` документацией, которая больше не
    описывает реальность, и делает это молча. У npm ту же роль бесплатно
    выполняет `npm ci`, отказываясь работать при расхождении lock и manifest;
    у pip аналога нет, потому что `.in` — не манифест, о котором pip знает.

    Транзитивные версии проверкой не покрыты: для них нужен настоящий прогон
    pip-compile в контейнере. Здесь закреплено то, что расходится на практике, —
    прямые зависимости.
    """

    def test_direct_pins_match_compiled_output(self) -> None:
        for source, compiled in (
            ("requirements.in", "requirements.txt"),
            ("requirements-dev.in", "requirements-dev.txt"),
        ):
            declared = _pins(source)
            resolved = _pins(compiled)
            assert declared, f"{source}: прямые зависимости не разобраны"

            for name, version in declared.items():
                assert name in resolved, f"{name} есть в {source}, но нет в {compiled}"
                assert resolved[name] == version, (
                    f"{name}: {source} закрепляет {version}, "
                    f"{compiled} — {resolved[name]}"
                )

    def test_compiled_files_stay_generated(self) -> None:
        # Заголовок pip-compile — единственный признак того, что файл получен
        # инструментом, а не написан руками. Его исчезновение означает, что
        # предыдущая проверка сравнивает две рукописи.
        for compiled in ("requirements.txt", "requirements-dev.txt"):
            body = (REPO_ROOT / compiled).read_text(encoding="utf-8")
            assert "autogenerated by pip-compile" in body, compiled
            assert "--generate-hashes" in body, compiled

    def test_every_pin_carries_hashes(self) -> None:
        # Версия говорит, какой релиз брать, но не что внутри него лежит.
        # Подмена артефакта в уже выпущенной версии закреплением не ловится.
        for compiled in ("requirements.txt", "requirements-dev.txt"):
            body = (REPO_ROOT / compiled).read_text(encoding="utf-8")
            packages = len(_pins(compiled))
            hashes = body.count("--hash=sha256:")
            assert packages > 0, compiled
            assert hashes >= packages, (
                f"{compiled}: {packages} пакетов, но только {hashes} хешей"
            )


class TestInstallFlags:
    """Установка зависимостей не исполняет чужой код.

    Питоновский эквивалент A51 из основного репозитория. Колёса при установке
    код не исполняют, а sdist исполняет `setup.py`, то есть даёт произвольное
    выполнение от одного факта установки. `--only-binary=:all:` запрещает sdist
    целиком, `--require-hashes` не даёт тихо поставить непроверенное.
    """

    @pytest.mark.parametrize(("workflow", "body"), _workflows())
    def test_workflow_installs_are_guarded(self, workflow: str, body: str) -> None:
        payload = "\n".join(
            line for line in body.splitlines() if not line.lstrip().startswith("#")
        )
        for install in re.findall(r"^\s*pip install[^\n]*", payload, re.MULTILINE):
            assert "--require-hashes" in install, f"{workflow}: {install.strip()}"
            assert "--only-binary=:all:" in install, f"{workflow}: {install.strip()}"

    def test_dockerfile_install_is_guarded(self) -> None:
        body = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        payload = "\n".join(
            line for line in body.splitlines() if not line.lstrip().startswith("#")
        )
        # Установка в образе одна, и она обязана нести оба флага.
        installs = re.findall(r"pip install[^\n]*(?:\\\n[^\n]*)*", payload)
        assert installs, "в Dockerfile не найдено ни одной установки"
        for install in installs:
            assert "--require-hashes" in install
            assert "--only-binary=:all:" in install

    def test_workflow_installs_are_found(self) -> None:
        # Предыдущие проверки проходят и на пустом списке совпадений.
        joined = "\n".join(body for _, body in _workflows())
        assert len(re.findall(r"^\s*pip install", joined, re.MULTILINE)) >= 2


class TestCycloneDxSbom:
    """Каждый deploy получает проверяемую опись ровно своего image digest.

    Attachment API — внешнее состояние GCP, поэтому pytest не доказывает, что
    сервис доступен. Он фиксирует более важные регрессии в нашей стороне
    контракта: tag/директория не заменяют digest, файл не принимается только за
    расширение, а ошибка публикации не превращается в информационный лог.
    """

    @pytest.fixture
    def workflow(self) -> str:
        return (WORKFLOWS_DIR / "deploy.yml").read_text(encoding="utf-8")

    @pytest.fixture
    def step(self, workflow: str) -> str:
        marker = "- name: Generate and attach CycloneDX SBOM"
        assert marker in workflow
        return workflow.split(marker, 1)[1].split("\n      - name:", 1)[0]

    def test_runs_after_build_and_before_deploy(self, workflow: str) -> None:
        build = workflow.index("- name: Build and push image")
        sbom = workflow.index("- name: Generate and attach CycloneDX SBOM")
        deploy = workflow.index("- name: Deploy to Cloud Run")
        assert build < sbom < deploy

    def test_syft_binary_is_versioned_and_checksum_verified(self, step: str) -> None:
        assert re.search(r"SYFT_VERSION:\s*\d+\.\d+\.\d+", step)
        assert re.search(r"SYFT_SHA256:\s*[0-9a-f]{64}", step)
        assert "sha256sum -c -" in step
        assert "syft_${SYFT_VERSION}_linux_amd64.tar.gz" in step

    def test_scans_exact_digest_as_cyclonedx_16(self, step: str) -> None:
        assert '[[ "${DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]' in step
        assert 'syft "${IMAGE}@${DIGEST}"' in step
        assert '-o "cyclonedx-json@1.6=${sbom}"' in step
        assert '.bomFormat == "CycloneDX"' in step
        assert '.specVersion == "1.6"' in step
        assert '.metadata.component.type == "container"' in step
        assert '.metadata.component.version == $digest' in step
        assert "((.components | length) > 0)" in step

    def test_attachment_targets_registry_version_by_digest(self, step: str) -> None:
        assert 'gcloud artifacts versions describe "${DIGEST}"' in step
        assert 'expected_target="projects/${PROJECT_ID}/locations/${REGION}' in step
        assert '/versions/${DIGEST}"' in step
        assert '[[ "${target}" == "${expected_target}" ]]' in step
        assert 'attachment_id="cyclonedx-${digest_hex:0:48}"' in step

    def test_attachment_is_idempotent_and_fail_closed(self, step: str) -> None:
        assert "gcloud artifacts attachments describe" in step
        assert "gcloud artifacts attachments create" in step
        assert '--attachment-type "${ATTACHMENT_TYPE}"' in step
        assert '--attachment-namespace "anchore.com/syft"' in step
        assert '--files "${sbom}"' in step
        assert ".target == $target" in step
        assert ".type == $type" in step
        assert "continue-on-error" not in step
        assert "actions/upload-artifact" not in step


class TestBuildKitProvenance:
    """Build output содержит подробный SLSA provenance exact digest.

    Это ещё не проверка signer identity: её даст keyless GitHub attestation.
    Здесь закреплены генерация `mode=max`, отсутствие каналов утечки build args
    и fail-closed проверка опубликованного документа до SBOM и deploy.
    """

    @pytest.fixture
    def workflow(self) -> str:
        return (WORKFLOWS_DIR / "deploy.yml").read_text(encoding="utf-8")

    @pytest.fixture
    def build_step(self, workflow: str) -> str:
        marker = "- name: Build and push image"
        assert marker in workflow
        return workflow.split(marker, 1)[1].split("\n      - name:", 1)[0]

    @pytest.fixture
    def verify_step(self, workflow: str) -> str:
        marker = "- name: Verify BuildKit provenance"
        assert marker in workflow
        return workflow.split(marker, 1)[1].split("\n      - name:", 1)[0]

    def test_mode_max_has_no_sensitive_input_channel(self, build_step: str) -> None:
        assert "provenance: mode=max,version=v1" in build_step
        for key in ("build-args:", "secrets:", "secret-envs:", "secret-files:"):
            assert (
                re.search(rf"^\s*{re.escape(key)}", build_step, re.MULTILINE)
                is None
            )

        dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        assert re.search(r"^\s*ARG(?:\s|$)", dockerfile, re.MULTILINE) is None

    def test_uses_attestation_capable_builder(self, workflow: str) -> None:
        setup = workflow.index("- name: Set up Docker Buildx")
        build = workflow.index("- name: Build and push image")
        assert setup < build
        setup_step = workflow[setup:build]
        assert "docker/setup-buildx-action@" in setup_step
        assert "driver: docker-container" in setup_step

    def test_verifies_exact_digest_before_sbom_and_deploy(self, workflow: str) -> None:
        build = workflow.index("- name: Build and push image")
        verify = workflow.index("- name: Verify BuildKit provenance")
        sbom = workflow.index("- name: Generate and attach CycloneDX SBOM")
        deploy = workflow.index("- name: Deploy to Cloud Run")
        assert build < verify < sbom < deploy

    def test_verifier_requires_detailed_slsa(self, verify_step: str) -> None:
        assert '[[ "${DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]' in verify_step
        assert 'imagetools inspect "${IMAGE}@${DIGEST}"' in verify_step
        assert "{{ json .Provenance.SLSA }}" in verify_step
        assert ".buildDefinition.buildType" in verify_step
        assert ".buildDefinition.resolvedDependencies" in verify_step
        assert (
            ".buildDefinition.internalParameters.buildConfig.llbDefinition"
            in verify_step
        )
        assert ".runDetails.metadata.buildkit_metadata.source.infos" in verify_step
        assert '.filename == "Dockerfile"' in verify_step
        assert "continue-on-error" not in verify_step


class TestGitHubArtifactAttestation:
    """Exact image подписывается keyless и проверяется до deploy."""

    @pytest.fixture
    def workflow(self) -> str:
        return (WORKFLOWS_DIR / "deploy.yml").read_text(encoding="utf-8")

    @pytest.fixture
    def verify_step(self, workflow: str) -> str:
        marker = "- name: Verify keyless GitHub artifact attestation"
        assert marker in workflow
        return workflow.split(marker, 1)[1].split("\n      - name:", 1)[0]

    def test_job_has_only_required_attestation_permissions(
        self, workflow: str
    ) -> None:
        deploy_job = workflow.split("\n  deploy:\n", 1)[1]
        permissions = deploy_job.split("\n    steps:\n", 1)[0]
        assert "contents: read" in permissions
        assert "id-token: write" in permissions
        assert "attestations: write" in permissions
        assert "artifact-metadata: write" in permissions
        assert "packages: write" not in permissions

    def test_signs_exact_build_output_with_pinned_action(self, workflow: str) -> None:
        step = workflow.split(
            "- name: Generate keyless GitHub artifact attestation", 1
        )[1].split("\n      - name:", 1)[0]
        assert (
            "uses: actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d"
            in step
        )
        assert "subject-name: ${{ env.IMAGE }}" in step
        assert "subject-digest: ${{ steps.build.outputs.digest }}" in step
        assert "push-to-registry" not in step

    def test_verifies_before_sbom_and_deploy(self, workflow: str) -> None:
        buildkit = workflow.index("- name: Verify BuildKit provenance")
        sign = workflow.index("- name: Generate keyless GitHub artifact attestation")
        verify = workflow.index("- name: Verify keyless GitHub artifact attestation")
        sbom = workflow.index("- name: Generate and attach CycloneDX SBOM")
        deploy = workflow.index("- name: Deploy to Cloud Run")
        assert buildkit < sign < verify < sbom < deploy

    def test_verifier_is_pinned_and_fail_closed(self, verify_step: str) -> None:
        assert "GH_CLI_VERSION: 2.98.0" in verify_step
        assert re.search(r"GH_CLI_SHA256:\s*[0-9a-f]{64}", verify_step)
        assert "sha256sum -c -" in verify_step
        assert '"${gh_bin}" attestation verify' in verify_step
        assert '"oci://${IMAGE}@${DIGEST}"' in verify_step
        assert "ATTESTATION_BUNDLE: ${{ steps.attest.outputs.bundle-path }}" in verify_step
        assert '[[ -s "${ATTESTATION_BUNDLE}" ]]' in verify_step
        assert '--bundle "${ATTESTATION_BUNDLE}"' in verify_step
        assert "--format json" in verify_step
        assert "continue-on-error" not in verify_step

    def test_enforces_signer_source_and_certificate_claims(
        self, verify_step: str
    ) -> None:
        for flag in (
            "--repo",
            "--signer-workflow",
            "--signer-digest",
            "--source-ref",
            "--source-digest",
            "--predicate-type",
            "--deny-self-hosted-runners",
        ):
            assert flag in verify_step
        assert '[[ "${GITHUB_EVENT_NAME}" == "push" ]]' in verify_step
        assert '[[ "${GITHUB_REF}" == "refs/heads/main" ]]' in verify_step
        assert ".buildTrigger" in verify_step
        assert ".runnerEnvironment" in verify_step
        assert ".sourceRepositoryIdentifier" in verify_step
        assert "python scripts/verify_attestation_certificate.py" in verify_step
        assert "--environment production" in verify_step
        assert "--event push" in verify_step
        assert "--runner github-hosted" in verify_step
        assert '--repository-id "${TRUSTED_REPOSITORY_ID}"' in verify_step
        assert 'TRUSTED_REPOSITORY_ID: \'1199475908\'' in verify_step
        assert ".verifiedTimestamps | length > 0" in verify_step


class TestRecurringImageScan:
    """Периодическая проверка смотрит на работающий immutable-артефакт.

    Эти контракты не доказывают доступность GitHub или GCP, но не дают тихо
    превратить fail-closed gate обратно в информационный deploy-time лог.
    """

    @pytest.fixture
    def workflow(self) -> str:
        return (WORKFLOWS_DIR / "image-scan.yml").read_text(encoding="utf-8")

    def test_runs_on_schedule_and_manually(self, workflow: str) -> None:
        assert re.search(r"^\s+schedule:\s*$", workflow, re.MULTILINE)
        assert re.search(r"^\s+workflow_dispatch:\s*$", workflow, re.MULTILINE)
        cron = re.search(r"cron:\s*['\"](\d+)\s", workflow)
        assert cron is not None
        assert cron.group(1) != "0"

    def test_policy_change_rescans_same_digest_without_redeploy(
        self, workflow: str
    ) -> None:
        deploy = (WORKFLOWS_DIR / "deploy.yml").read_text(encoding="utf-8")
        policy_paths = (
            "security/vex/**",
            "security/waivers.json",
            "scripts/evaluate_image_scan.py",
            "scripts/verify_image_evidence.py",
            ".github/workflows/image-scan.yml",
        )

        assert re.search(r"^\s+push:\s*$", workflow, re.MULTILINE)
        assert re.search(r"^\s+paths:\s*$", workflow, re.MULTILINE)
        assert re.search(r"^\s+paths-ignore:\s*$", deploy, re.MULTILINE)
        for path in policy_paths:
            assert f"- {path}" in workflow
            assert f"- {path}" in deploy

    def test_uses_dedicated_read_only_identity(self, workflow: str) -> None:
        assert "github-image-scanner@" in workflow
        assert "service_account: ${{ env.SCANNER_SA }}" in workflow
        assert "service_account: github-deployer@" not in workflow
        assert "gcloud run deploy" not in workflow
        assert "docker/build-push-action" not in workflow

    def test_resolves_cloud_run_revisions_to_expected_digests(
        self, workflow: str
    ) -> None:
        assert "gcloud run services describe" in workflow
        assert "gcloud run revisions describe" in workflow
        assert "(.percent // 0) > 0" in workflow
        assert ".tag != null" in workflow
        assert 'prefix="${IMAGE}@sha256:"' in workflow
        assert "^[0-9a-f]{64}$" in workflow

    def test_scan_is_fail_closed_for_high_and_critical(self, workflow: str) -> None:
        payload = "\n".join(
            line for line in workflow.splitlines()
            if not line.lstrip().startswith("#")
        )
        assert 'grype "${image_ref}" -o json --file "${raw_report}"' in payload
        assert "python scripts/evaluate_image_scan.py" in payload
        assert '--image-digest "${digest}"' in payload
        assert "--vex-dir security/vex" in payload
        assert "--waivers security/waivers.json" in payload
        assert "if (( scan_code != 0 ))" in payload
        assert "if (( policy_code != 0 ))" in payload
        assert "--fail-on" not in payload
        assert "--only-fixed" not in payload
        assert "continue-on-error" not in payload
        assert "GRYPE_DB_REQUIRE_UPDATE_CHECK: 'true'" in payload
        assert "GRYPE_DB_VALIDATE_AGE: 'true'" in payload
        assert "grype db update" in payload

    def test_collects_runtime_evidence_without_running_image(
        self, workflow: str
    ) -> None:
        payload = "\n".join(
            line for line in workflow.splitlines()
            if not line.lstrip().startswith("#")
        )
        assert 'docker pull "${image_ref}"' in payload
        assert 'docker image inspect "${image_ref}"' in payload
        assert 'docker create "${image_ref}"' in payload
        assert 'docker export --output "${rootfs_tar}" "${container_id}"' in payload
        assert "python scripts/verify_image_evidence.py" in payload
        assert '--image-ref "${image_ref}"' in payload
        assert '--image-digest "${digest}"' in payload
        assert '--output "${evidence_report}"' in payload
        assert "if (( evidence_code != 0 ))" in payload
        assert '[[ ! -f "${evidence_report}" ]]' in payload
        assert "docker run" not in payload

    def test_policy_is_loaded_from_reviewed_main_checkout(self, workflow: str) -> None:
        assert "actions/checkout@" in workflow
        assert "persist-credentials: false" in workflow
        assert "python-version: '3.13'" in workflow

    def test_reports_survive_a_failed_gate(self, workflow: str) -> None:
        assert "if: always()" in workflow
        assert "retention-days: 30" in workflow
        assert "${report_prefix}-raw.json" in workflow
        assert "${report_prefix}-policy.json" in workflow
        assert "${report_prefix}-evidence.json" in workflow
