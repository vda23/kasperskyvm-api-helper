#!/usr/bin/env bash
#
# kasperskyvm-api-helper.sh — скрипт, позволяющий интерактивно выгружать данные из Kaspersky Vulnerability Management по API.
#
# Получает токен сессии в Kaspersky Security Center,
# постранично выгружает активы, уязвимости или ПО и сохраняет каждый набор в один JSON-файл
# в папку, где лежит скрипт.
#
# Зависимости: bash 4+, curl, coreutils, grep, sed. Для склейки страниц используется python3
# или jq; если нет ни того, ни другого, работает встроенный разбор формата ответа API.
#
# Запустите с --help, чтобы увидеть все параметры.

if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  echo "Нужен bash версии 4 или новее." >&2
  exit 1
fi

set -Eeuo pipefail
shopt -s nullglob

readonly VERSION="1.1.0"
readonly SCRIPT_NAME="${0##*/}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
# Порты фиксированы: пользователь вводит только FQDN.
# Для нестандартной инсталляции поменяйте значения здесь.
readonly KSC_PORT=13299
readonly KVM_PORT=5054
readonly MAX_PAGE_SIZE=10000

readonly TYPES=(assets vulnerabilities software)
declare -Ar ENDPOINTS=(
  [assets]="/v1/assets"
  [vulnerabilities]="/v1/vulnerabilities/detections"
  [software]="/v1/software"
)
declare -Ar LABELS=([assets]="Активы" [vulnerabilities]="Уязвимости" [software]="ПО")

KSC_ADDR="" KVM_ADDR="" KSC_USER="" KSC_PASS="${KSC_PASSWORD:-}"
PAGE_SIZE=$MAX_PAGE_SIZE OUT_DIR=$SCRIPT_DIR CACERT="" RUN_TYPE=""
TOKEN="" WORK_DIR=""
# Фильтры выгрузки (пусто — без фильтра)
F_IP="" F_IMPORTANCE="" F_PRIORITY="" F_NAME=""
API_FILTERS="" LOCAL_FILTER="" FILTER_DESC=""
readonly IMPORTANCE_NAMES=("не задана" "низкая" "средняя" "высокая" "критическая")
readonly PRIORITY_NAMES=("не задан" "низкий" "средний" "высокий" "критический")
TLS_OPTS=()

# ──────────────────────────────── Оформление ────────────────────────────────

setup_ui() {
  C_RESET="" C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW="" C_CYAN=""
  IS_TTY=0
  if [[ -t 2 ]]; then IS_TTY=1; fi
  if (( IS_TTY )) && [[ -z ${NO_COLOR:-} && ${TERM:-dumb} != dumb ]]; then
    C_RESET=$'\e[0m' C_BOLD=$'\e[1m' C_DIM=$'\e[2m'
    C_RED=$'\e[31m' C_GREEN=$'\e[32m' C_YELLOW=$'\e[33m' C_CYAN=$'\e[36m'
  fi
  if [[ ${LC_ALL:-${LC_CTYPE:-${LANG:-}}} =~ [Uu][Tt][Ff]-?8 ]]; then
    S_OK="✔" S_ERR="✖" S_WARN="▲" S_INFO="›" S_LINE="─" BAR_ON="█" BAR_OFF="░"
    SPIN=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
  else
    S_OK="+" S_ERR="x" S_WARN="!" S_INFO=">" S_LINE="-" BAR_ON="#" BAR_OFF="."
    SPIN=('|' '/' '-' '\')
  fi
}

info()  { printf '  %s %s\n' "${C_CYAN}${S_INFO}${C_RESET}" "$*" >&2; }
ok()    { printf '  %s %s\n' "${C_GREEN}${S_OK}${C_RESET}" "$*" >&2; }
warn()  { printf '  %s %s\n' "${C_YELLOW}${S_WARN}${C_RESET}" "$*" >&2; }
err()   { printf '  %s\n' "${C_RED}${S_ERR} $*${C_RESET}" >&2; }
die()   { err "$*"; exit 1; }
rule()  { local l; printf -v l '%*s' 60 ''; printf '%s\n' "${C_DIM}${l// /$S_LINE}${C_RESET}" >&2; }
title() { printf '\n  %s\n' "${C_BOLD}$*${C_RESET}" >&2; rule; }
cursor_hide() { if (( IS_TTY )); then printf '\e[?25l' >&2; fi; }
cursor_show() { if (( IS_TTY )); then printf '\e[?25h' >&2; fi; }

banner() {
  printf '\n  %s  %s\n' "${C_BOLD}Kaspersky VM: выгрузка данных по API${C_RESET}" "${C_DIM}v${VERSION}${C_RESET}" >&2
  rule
}

usage() {
  cat <<EOF
Выгрузка данных из Kaspersky Vulnerability Management в JSON-файлы.

Использование:
  ${SCRIPT_NAME} [параметры]

Без параметров запускается интерактивное меню. С параметром -t выгрузка идёт без меню.

Параметры:
  --ksc FQDN          FQDN Kaspersky Security Center (порт ${KSC_PORT} подставляется сам)
  --kvm FQDN          FQDN Kaspersky VM (порт ${KVM_PORT} подставляется сам)
  -u, --user ИМЯ      Пользователь KSC
  -t, --type ТИП      assets | vulnerabilities | software | all — выгрузить без меню
  -s, --page-size N   Записей на странице, 1–${MAX_PAGE_SIZE} (по умолчанию ${MAX_PAGE_SIZE})
  -o, --output DIR    Папка для файлов (по умолчанию папка скрипта)
      --cacert FILE   Проверять TLS-сертификаты серверов по файлу PEM (см. --tls-help)
      --tls-help      Как включить проверку TLS-сертификатов, по шагам
      --no-color      Без цветов
  -h, --help          Эта справка
  -V, --version       Версия

Фильтры (в меню скрипт спросит их сам):
  --ip СПИСОК         Активы: IP-адреса через запятую или часть адреса, например 10.68.
  --importance N[,N]  Активы: значимость, 4 — критическая, 3 — высокая, 2 — средняя,
                      1 — низкая, 0 — не задана
  --priority N[,N]    Уязвимости: приоритет устранения, 4 — критический … 0 — не задан
  --name ТЕКСТ        ПО: имя или его часть, без учёта регистра (python найдёт python3-pexpect)

Если для активов заданы и IP, и значимость, выгружаются активы, подходящие под оба условия.

Пароль спрашивается при запуске; для автоматического режима его можно передать
в переменной окружения KSC_PASSWORD.

Примеры:
  ./${SCRIPT_NAME}
  ./${SCRIPT_NAME} --ksc ksc.corp.local -u admin -t vulnerabilities
  ./${SCRIPT_NAME} --ksc ksc.corp.local -u admin -t vulnerabilities --priority 4,3
  ./${SCRIPT_NAME} --ksc ksc.corp.local -u admin -t software --name python
  KSC_PASSWORD='***' ./${SCRIPT_NAME} --ksc ksc.corp.local --kvm kvm.corp.local -u admin -t all
EOF
}

tls_help() {
  cat <<EOF
Проверка TLS-сертификатов

По умолчанию скрипт не проверяет сертификаты KSC и Kaspersky VM, как curl -k.
Трафик всё равно шифруется, но без проверки скрипт не заметит подмену сервера:
пароль и токен могут уйти на чужой узел. Чтобы включить проверку, нужен файл
с доверенными сертификатами в формате PEM.

1. Получите сертификаты.

   Если сертификаты серверов выпущены корпоративным центром сертификации,
   попросите у администратора PKI корневой сертификат CA (.pem или .crt
   в формате Base64) и переходите к шагу 3.

   Если серверы используют собственные сертификаты (по умолчанию так и есть),
   сохраните их прямо с серверов:

     openssl s_client -connect <FQDN KSC>:${KSC_PORT} -servername <FQDN KSC> -showcerts </dev/null 2>/dev/null \\
       | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > ksc.pem

     openssl s_client -connect <FQDN VM>:${KVM_PORT} -servername <FQDN VM> -showcerts </dev/null 2>/dev/null \\
       | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > kvm.pem

2. Убедитесь, что сохранили сертификаты именно ваших серверов.

     openssl x509 -in ksc.pem -noout -subject -issuer -enddate -fingerprint -sha256
     openssl x509 -in kvm.pem -noout -subject -issuer -enddate -fingerprint -sha256

   Сверьте отпечаток SHA-256 с сертификатом в свойствах сервера в консоли KSC
   или с файлом сертификата на самом сервере. Этот шаг защищает от того,
   что на шаге 1 вы получили сертификат подменённого узла.

   Сертификат должен быть выписан на тот FQDN, который вы вводите в скрипте
   (поле CN или SAN). Если там другое имя или IP-адрес, curl откажет
   в соединении, и нужно вводить в скрипте именно то имя.

3. Объедините сертификаты в один файл:

     cat ksc.pem kvm.pem > ca-bundle.pem

4. Проверьте, что curl доверяет обоим серверам (ошибок быть не должно):

     curl -sS --cacert ca-bundle.pem -o /dev/null https://<FQDN KSC>:${KSC_PORT}/
     curl -sS --cacert ca-bundle.pem -o /dev/null https://<FQDN VM>:${KVM_PORT}/

5. Запускайте скрипт с проверкой:

     ./${SCRIPT_NAME} --cacert ca-bundle.pem

Когда сертификат сервера перевыпустят, повторите шаги 1–3.
EOF
}

# ──────────────────────────────── Утилиты ────────────────────────────────

have() { command -v "$1" >/dev/null 2>&1; }

trim() {
  local s=$1
  s="${s#"${s%%[![:space:]]*}"}"
  printf '%s' "${s%"${s##*[![:space:]]}"}"
}

fmt_num() {
  local n=$1 r=""
  while (( ${#n} > 3 )); do r=" ${n: -3}${r}"; n=${n:0:${#n}-3}; done
  printf '%s%s' "$n" "$r"
}

fmt_size() {
  awk -v b="$1" 'BEGIN { split("Б КБ МБ ГБ", u, " "); i = 1
    while (b >= 1024 && i < 4) { b /= 1024; i++ }
    printf (i == 1 ? "%d %s" : "%.1f %s"), b, u[i] }'
}

fmt_dur() {
  local s=$1
  if (( s >= 60 )); then printf '%d мин %02d с' $(( s / 60 )) $(( s % 60 )); else printf '%d с' "$s"; fi
}

plural() {  # plural N "запись" "записи" "записей"
  local n=$(( $1 % 100 )) m=$(( $1 % 10 ))
  if (( n >= 11 && n <= 14 )); then printf '%s' "$4"
  elif (( m == 1 )); then printf '%s' "$2"
  elif (( m >= 2 && m <= 4 )); then printf '%s' "$3"
  else printf '%s' "$4"; fi
}

file_size() { stat -c %s -- "$1" 2>/dev/null || wc -c < "$1"; }

strip_scheme() { local a=${1#http://}; a=${a#https://}; printf '%s' "${a%%/*}"; }
valid_fqdn()   { [[ $1 =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; }
to_fqdn()      { local a; a=$(strip_scheme "$1"); printf '%s' "${a%%:*}"; }   # убирает схему, путь и порт
host_of()      { local a=${1#https://}; printf '%s' "${a%%:*}"; }             # https://хост:порт -> хост

ask() {  # ask ПЕРЕМЕННАЯ "Вопрос" [значение по умолчанию]
  local var=$1 prompt=$2 def=${3:-} ans=""
  while true; do
    if [[ -n $def ]]; then
      read -rp "  ${prompt} ${C_DIM}[${def}]${C_RESET}: " ans || die "Ввод прерван."
      ans=${ans:-$def}
    else
      read -rp "  ${prompt}: " ans || die "Ввод прерван."
    fi
    ans=$(trim "$ans")
    if [[ -n $ans ]]; then break; fi
    warn "Значение не может быть пустым."
  done
  printf -v "$var" '%s' "$ans"
}

ask_secret() {  # ask_secret ПЕРЕМЕННАЯ "Вопрос"
  local var=$1 prompt=$2 ans=""
  while true; do
    read -rsp "  ${prompt}: " ans || die "Ввод прерван."
    printf '\n' >&2
    if [[ -n $ans ]]; then break; fi
    warn "Пароль не может быть пустым."
  done
  printf -v "$var" '%s' "$ans"
}

ask_fqdn() {  # ask_fqdn ПЕРЕМЕННАЯ "Вопрос" ПОРТ [FQDN по умолчанию] -> https://fqdn:порт
  local var=$1 prompt=$2 port=$3 def=${4:-} raw="" v=""
  while true; do
    ask raw "$prompt" "$def"
    v=$(to_fqdn "$raw")
    if valid_fqdn "$v"; then break; fi
    warn "Укажите только FQDN, например ksc.corp.local"
  done
  if [[ $(strip_scheme "$raw") == *:* ]]; then info "Порт указывать не нужно: используется ${port}."; fi
  printf -v "$var" 'https://%s:%s' "$v" "$port"
}

confirm() {  # confirm "Вопрос" -> 0, если ответ «да» (по умолчанию «да»)
  local a=""
  read -rp "  $1 ${C_DIM}[Д/н]${C_RESET}: " a || return 1
  [[ -z $a || $a =~ ^[ДдYy] ]]
}

confirm_no() {  # confirm_no "Вопрос" -> 0, если ответ «да» (по умолчанию «нет»)
  local a=""
  read -rp "  $1 ${C_DIM}[д/Н]${C_RESET}: " a || return 1
  [[ $a =~ ^[ДдYy] ]]
}

spin() {  # spin "Подпись" команда... — крутит индикатор, пока идёт команда
  local label=$1
  shift
  if (( ! IS_TTY )); then "$@"; return; fi
  "$@" &
  local pid=$! i=0 rc=0
  cursor_hide
  while kill -0 "$pid" 2>/dev/null; do
    printf '\r  %s %s' "${C_CYAN}${SPIN[i % ${#SPIN[@]}]}${C_RESET}" "$label" >&2
    i=$(( i + 1 ))
    sleep 0.1
  done
  wait "$pid" || rc=$?
  printf '\r\e[K' >&2
  cursor_show
  return "$rc"
}

progress_line() {  # progress_line СТРАНИЦА ВСЕГО_СТРАНИЦ ПОЛУЧЕНО ВСЕГО_ЗАПИСЕЙ СЕКУНДЫ БАЙТЫ
  local page=$1 pages=$2 got=$3 total=$4 secs=$5 bytes=$6 width=24 filled on off
  if (( total > 0 )); then filled=$(( got * width / total )); else filled=$width; fi
  printf -v on  '%*s' "$filled" '';             on=${on// /$BAR_ON}
  printf -v off '%*s' $(( width - filled )) ''; off=${off// /$BAR_OFF}
  printf '  %s Стр. %*d/%d  %s%s%s%s  %11s  %s\n' \
    "${C_GREEN}${S_OK}${C_RESET}" "${#pages}" "$page" "$pages" \
    "$C_CYAN" "$on" "${C_DIM}${off}" "$C_RESET" "$(fmt_num "$got")" \
    "${C_DIM}$(fmt_size "$bytes"), $(fmt_dur "$secs")${C_RESET}" >&2
}

# ──────────────────────────────── HTTP и сессия KSC ────────────────────────────────

curl_quote() { local s=${1//\\/\\\\}; printf '%s' "${s//\"/\\\"}"; }
b64()        { printf '%s' "$1" | base64 | tr -d '\n'; }

# api_post URL ФАЙЛ ТЕЛО [ЗАГОЛОВОК...] — печатает HTTP-код ответа.
# Заголовки передаются в curl через stdin (--config -), поэтому пароль и токен
# не видны другим пользователям в списке процессов.
api_post() {
  local url=$1 out=$2 body=$3 cfg="" h
  shift 3
  for h in "$@"; do cfg+="header = \"$(curl_quote "$h")\""$'\n'; done
  curl --silent --show-error "${TLS_OPTS[@]}" \
       --connect-timeout 15 --max-time 1800 --retry 3 --retry-delay 3 \
       --request POST --header 'Content-Type: application/json' --data "$body" \
       --output "$out" --write-out '%{http_code}' --config - "$url" <<<"$cfg"
}

start_session() {
  local f="${WORK_DIR}/session.json" code="" msg=""
  TOKEN=""
  if ! code=$(spin "Получаю токен в KSC…" api_post "${KSC_ADDR}/api/v1.0/Session.StartSession" "$f" '{}' \
      "Authorization: KSCBasic user=\"$(b64 "$KSC_USER")\", pass=\"$(b64 "$KSC_PASS")\", internal=\"1\""); then
    err "Нет связи с KSC: ${KSC_ADDR}$(tls_hint)"
    return 1
  fi
  TOKEN=$(grep -o '"PxgRetVal":"[^"]*"' "$f" | cut -d'"' -f4) || true
  if [[ -z $TOKEN ]]; then
    msg=$(grep -o '"message":"[^"]*"' "$f" | head -n1 | cut -d'"' -f4) || true
    rm -f -- "$f"
    if [[ $code == 401 ]]; then
      err "KSC отклонил вход (HTTP 401): проверьте имя пользователя и пароль."
    else
      err "KSC не выдал токен (HTTP ${code})${msg:+: ${msg}}"
    fi
    return 1
  fi
  rm -f -- "$f"
  ok "Сессия KSC открыта: ${KSC_USER} @ ${KSC_ADDR#https://}"
}

tls_hint() {  # подсказка к сетевой ошибке, когда включена проверка сертификатов
  if [[ -n $CACERT ]]; then printf '. Если выше ошибка сертификата, см. %s --tls-help' "$SCRIPT_NAME"; fi
}

end_session() {
  if [[ -z ${TOKEN:-} ]]; then return 0; fi
  api_post "${KSC_ADDR}/api/v1.0/Session.EndSession" /dev/null '{}' "X-KSC-Session: ${TOKEN}" >/dev/null 2>&1 || true
  TOKEN=""
}

fetch_page() {  # fetch_page URL СТРАНИЦА ФАЙЛ "Подпись" — фильтры берутся из API_FILTERS
  local url=$1 page=$2 out=$3 label=$4 code="" attempt head body
  body="{\"page\": ${page}, \"pageSize\": ${PAGE_SIZE}${API_FILTERS:+, \"filters\": ${API_FILTERS}}}"
  for attempt in 1 2; do
    if ! code=$(spin "$label" api_post "$url" "$out" "$body" "X-KSC-Session: ${TOKEN}"); then
      err "Нет связи с Kaspersky VM: ${url}$(tls_hint)"
      return 1
    fi
    head=$(head -c 300 -- "$out")
    if [[ $code == 2* && $head == *'"success":true'* ]]; then return 0; fi
    if [[ $attempt == 1 && ( $code == 401 || $head == *'"code":401'* ) ]]; then
      warn "Сессия KSC истекла, получаю новый токен…"
      start_session || return 1
      continue
    fi
    err "Kaspersky VM вернул ошибку на странице ${page} (HTTP ${code}): ${head}"
    return 1
  done
}

# ──────────────────────────────── Фильтры ────────────────────────────────

json_str() {  # json_str ТЕКСТ -> "текст" с экранированием для JSON
  local s
  s=$(printf '%s' "$1" | tr -d '[:cntrl:]')
  s=${s//\\/\\\\}
  printf '"%s"' "${s//\"/\\\"}"
}

is_full_ip() {  # полный IPv4 или IPv6-адрес
  [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || $1 =~ ^[0-9A-Fa-f]*:[0-9A-Fa-f]*:[0-9A-Fa-f:.]*$ ]]
}

ip_filter_item() {  # ip_filter_item "10.0.0.1,10.0.0.2" | "10.68." -> элемент фильтра API
  local raw=${1// /} item list="" items=()
  IFS=',' read -ra items <<<"$raw"
  if (( ${#items[@]} == 1 )) && ! is_full_ip "${items[0]}"; then
    [[ ${items[0]} =~ ^[0-9A-Fa-f:.]+$ ]] || return 1
    printf '{"op":"contains","v":"%s"}' "${items[0]}"
    return 0
  fi
  (( ${#items[@]} > 0 )) || return 1
  for item in "${items[@]}"; do
    is_full_ip "$item" || return 1
    list+="${list:+,}\"${item}\""
  done
  printf '{"op":"include","v":[%s]}' "$list"
}

ip_desc() {  # человекочитаемое описание фильтра по IP
  local raw=${1// /}
  if [[ $raw != *,* ]] && ! is_full_ip "$raw"; then printf 'IP содержит «%s»' "$raw"; else printf 'IP: %s' "${raw//,/, }"; fi
}

norm_levels() {  # "3, 4,3" -> "4,3"; пусто и код 1, если есть значения вне 0–4
  local raw=${1// /}
  [[ $raw =~ ^[0-4](,[0-4])*$ ]] || return 1
  printf '%s' "$raw" | tr ',' '\n' | sort -rnu | paste -sd, -
}

level_names() {  # level_names "4,3" importance|priority -> "критическая, высокая"
  local v out="" names=()
  if [[ $2 == importance ]]; then names=("${IMPORTANCE_NAMES[@]}"); else names=("${PRIORITY_NAMES[@]}"); fi
  for v in ${1//,/ }; do out+="${out:+, }${names[v]}"; done
  printf '%s' "$out"
}

can_filter_locally() { have python3 || have jq; }

ask_opt() {  # ask_opt ПЕРЕМЕННАЯ "Вопрос" — необязательный ввод, Enter — пропустить
  local ans=""
  read -rp "  $2 ${C_DIM}[Enter — пропустить]${C_RESET}: " ans || die "Ввод прерван."
  printf -v "$1" '%s' "$(trim "$ans")"
}

ask_filters() {  # ask_filters ТИП — спрашивает фильтры для одного типа данных
  local v=""
  case $1 in
    assets)
      printf '\n  %s\n' "${C_BOLD}Фильтры для активов${C_RESET}" >&2
      while true; do
        ask_opt v "IP-адрес: полный (можно несколько через запятую) или часть, например 10.68."
        if [[ -z $v ]] || ip_filter_item "$v" >/dev/null; then F_IP=${v// /}; break; fi
        warn "Не похоже на IP-адрес. Примеры: 10.0.0.5 | 10.0.0.5, 10.0.0.6 | 10.68."
      done
      info "Значимость: 4 — критическая, 3 — высокая, 2 — средняя, 1 — низкая, 0 — не задана"
      while true; do
        ask_opt v "Значимость, одно или несколько значений через запятую"
        if [[ -z $v ]]; then F_IMPORTANCE=""; break; fi
        if F_IMPORTANCE=$(norm_levels "$v"); then
          if [[ -n $F_IP ]] && ! can_filter_locally; then
            warn "Для сочетания IP и значимости нужен python3 или jq. Оставьте только один фильтр."
            F_IMPORTANCE=""
            continue
          fi
          break
        fi
        warn "Допустимы числа от 0 до 4 через запятую, например 4,3"
      done
      ;;
    vulnerabilities)
      printf '\n  %s\n' "${C_BOLD}Фильтры для уязвимостей${C_RESET}" >&2
      info "Приоритет устранения: 4 — критический, 3 — высокий, 2 — средний, 1 — низкий, 0 — не задан"
      while true; do
        ask_opt v "Приоритет, одно или несколько значений через запятую"
        if [[ -z $v ]]; then F_PRIORITY=""; break; fi
        if F_PRIORITY=$(norm_levels "$v"); then break; fi
        warn "Допустимы числа от 0 до 4 через запятую, например 4,3"
      done
      ;;
    software)
      printf '\n  %s\n' "${C_BOLD}Фильтры для ПО${C_RESET}" >&2
      ask_opt F_NAME "Имя ПО или его часть, регистр не важен (например, python)"
      ;;
  esac
}

build_filters() {  # build_filters ТИП — заполняет API_FILTERS, LOCAL_FILTER и FILTER_DESC
  local parts=() desc=()
  API_FILTERS="" LOCAL_FILTER="" FILTER_DESC=""
  case $1 in
    assets)
      if [[ -n $F_IP ]]; then
        parts+=("\"ipAddresses\":[$(ip_filter_item "$F_IP")]")
        desc+=("$(ip_desc "$F_IP")")
      fi
      if [[ -n $F_IMPORTANCE ]]; then
        # API объединяет разные поля фильтра через ИЛИ. Чтобы получить «IP И значимость»,
        # по IP фильтрует сервер, а по значимости — скрипт при сборке файла.
        if [[ -n $F_IP ]]; then
          LOCAL_FILTER="importance:${F_IMPORTANCE}"
        else
          parts+=("\"importance\":[{\"op\":\"=\",\"v\":[${F_IMPORTANCE}]}]")
        fi
        desc+=("значимость: $(level_names "$F_IMPORTANCE" importance)")
      fi
      ;;
    vulnerabilities)
      if [[ -n $F_PRIORITY ]]; then
        parts+=("\"priority\":[{\"op\":\"=\",\"v\":[${F_PRIORITY}]}]")
        desc+=("приоритет: $(level_names "$F_PRIORITY" priority)")
      fi
      ;;
    software)
      if [[ -n $F_NAME ]]; then
        parts+=("\"name\":[{\"op\":\"contains\",\"v\":$(json_str "$F_NAME")}]")
        desc+=("имя содержит «${F_NAME}»")
      fi
      ;;
  esac
  if (( ${#parts[@]} )); then API_FILTERS="{$(IFS=,; printf '%s' "${parts[*]}")}"; fi
  if (( ${#desc[@]} )); then
    FILTER_DESC=${desc[0]}
    if (( ${#desc[@]} > 1 )); then FILTER_DESC+=" и ${desc[1]}"; fi
  fi
}

clear_filters() { F_IP="" F_IMPORTANCE="" F_PRIORITY="" F_NAME=""; }

# ──────────────────────────────── Выгрузка ────────────────────────────────

merge_pages() {  # merge_pages ПАПКА ФАЙЛ ОЖИДАЕМО [ПОЛЕ:ЗНАЧЕНИЯ] — пишет {"data":[...], и печатает число записей
  local dir=$1 out=$2 expected=$3 local_filter=${4:-} f sep="" head tail
  local files=("$dir"/*.json)
  if have python3; then
    python3 - "$out" "$local_filter" "${files[@]}" <<'PY'
import json, sys
out, flt, files = sys.argv[1], sys.argv[2], sys.argv[3:]
key, allowed = None, None
if flt:
    key, values = flt.split(":", 1)
    allowed = {int(v) for v in values.split(",")}
n = 0
with open(out, "w", encoding="utf-8") as o:
    o.write('{"data":[')
    for path in files:
        with open(path, encoding="utf-8") as fh:
            for item in json.load(fh).get("data", []):
                if key and item.get(key) not in allowed:
                    continue
                if n:
                    o.write(",")
                json.dump(item, o, ensure_ascii=False, separators=(",", ":"))
                n += 1
    o.write("],")
print(n)
PY
  elif have jq; then
    local ndjson="${dir}/items.ndjson" key="" values="[]"
    if [[ -n $local_filter ]]; then key=${local_filter%%:*}; values="[${local_filter#*:}]"; fi
    for f in "${files[@]}"; do
      jq -c --arg k "$key" --argjson a "$values" \
        '.data[] | select($k == "" or (.[$k] as $v | $a | index($v)) != null)' "$f"
    done > "$ndjson"
    { printf '{"data":['; paste -sd, - < "$ndjson"; printf '],'; } > "$out"
    wc -l < "$ndjson" | tr -d ' '
  else
    if [[ -n $local_filter ]]; then
      err "Для сочетания фильтров нужен python3 или jq."
      return 1
    fi
    printf '{"data":[' > "$out"
    for f in "${files[@]}"; do
      head=$(head -c 25 -- "$f")
      tail=$(tail -c 160 -- "$f")
      if [[ $head != '{"success":true,"data":['* || $tail != *'],"meta":{"pagination":{'*'}}}'* ]]; then
        err "Неизвестный формат ответа API. Установите python3 или jq и повторите."
        return 1
      fi
      if [[ $head == '{"success":true,"data":[]' ]]; then continue; fi
      printf '%s' "$sep" >> "$out"
      sed -e '1s/^{"success":true,"data":\[//' \
          -e '$s/\],"meta":{"pagination":{[^{}]*}}}[[:space:]]*$//' -- "$f" >> "$out"
      sep=","
    done
    printf '],' >> "$out"
    printf '%s\n' "$expected"
  fi
}

export_type() {  # export_type assets|vulnerabilities|software
  local type=$1
  local label=${LABELS[$type]} url="${KVM_ADDR}${ENDPOINTS[$type]}"
  local dir="${WORK_DIR}/${type}" page=1 pages=1 total=0 got f t_start=$SECONDS t_page step out count=""

  build_filters "$type"
  title "${label}"
  info "POST ${url}"
  if [[ -n $FILTER_DESC ]]; then info "Фильтр: ${C_BOLD}${FILTER_DESC}${C_RESET}"; fi
  rm -rf -- "$dir"
  mkdir -p -- "$dir"

  while (( page <= pages )); do
    f="${dir}/$(printf '%05d' "$page").json"
    if (( page == 1 )); then step="Запрашиваю первую страницу…"; else step="Страница ${page} из ${pages}…"; fi
    t_page=$SECONDS
    fetch_page "$url" "$page" "$f" "$step" || return 1

    if (( page == 1 )); then
      total=$(tail -c 512 -- "$f" | grep -o '"total":[0-9]*' | tail -n1 | cut -d: -f2) || true
      if [[ -z $total ]]; then
        err "В ответе нет meta.pagination.total, не могу посчитать число страниц."
        return 1
      fi
      if (( total == 0 )); then
        rm -rf -- "$dir"
        warn "${label}: по заданным условиям ничего не найдено, файл не создан."
        return 0
      fi
      pages=$(( (total + PAGE_SIZE - 1) / PAGE_SIZE ))
      if (( pages < 1 )); then pages=1; fi
      info "На сервере ${C_BOLD}$(fmt_num "$total")${C_RESET} $(plural "$total" запись записи записей): ${pages} стр. по $(fmt_num "$PAGE_SIZE")"
    fi

    got=$(( page * PAGE_SIZE < total ? page * PAGE_SIZE : total ))
    progress_line "$page" "$pages" "$got" "$total" $(( SECONDS - t_page )) "$(file_size "$f")"
    page=$(( page + 1 ))
  done

  out="${OUT_DIR}/kasperskyvm_${type}_$(date +%Y-%m-%d_%H-%M-%S).json"
  if ! count=$(spin "Собираю единый JSON-файл…" merge_pages "$dir" "${out}.part" "$total" "$LOCAL_FILTER"); then
    rm -f -- "${out}.part"
    err "Не удалось собрать файл."
    return 1
  fi
  local local_json="null"
  if [[ -n $LOCAL_FILTER ]]; then local_json="{\"${LOCAL_FILTER%%:*}\":[${LOCAL_FILTER#*:}]}"; fi
  printf '"meta":{"type":"%s","source":"%s","exportedAt":"%s","filters":%s,"localFilter":%s,"total":%s,"count":%s,"pages":%s}}\n' \
    "$type" "$url" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${API_FILTERS:-null}" "$local_json" \
    "$total" "$count" "$pages" >> "${out}.part"
  mv -f -- "${out}.part" "$out"
  rm -rf -- "$dir"

  ok "${label}: ${C_BOLD}$(fmt_num "$count")${C_RESET} $(plural "$count" запись записи записей) за $(fmt_dur $(( SECONDS - t_start )))"
  ok "Файл: ${C_BOLD}${out}${C_RESET} ${C_DIM}($(fmt_size "$(file_size "$out")"))${C_RESET}"
  if [[ -n $LOCAL_FILTER ]]; then
    info "Из $(fmt_num "$total") $(plural "$total" актива активов активов) с подходящим IP по значимости отобрано $(fmt_num "$count")."
  elif [[ $count != "$total" ]]; then
    warn "Сервер сообщил $(fmt_num "$total") записей: данные могли измениться во время выгрузки."
  fi
}

run_export() {  # run_export ТИП|all — возвращает число неудачных выгрузок
  local t failed=0 list=()
  if [[ $1 == all ]]; then list=("${TYPES[@]}"); else list=("$1"); fi
  if [[ -z $TOKEN ]]; then start_session || return 1; fi
  for t in "${list[@]}"; do
    export_type "$t" || failed=$(( failed + 1 ))
  done
  return "$failed"
}

# ──────────────────────────────── Настройки ────────────────────────────────

parse_args() {
  local v
  while (( $# )); do
    case $1 in
      -h|--help)      usage; exit 0 ;;
      -V|--version)   printf '%s %s\n' "$SCRIPT_NAME" "$VERSION"; exit 0 ;;
      --tls-help)     tls_help; exit 0 ;;
      --no-color)     NO_COLOR=1; setup_ui; shift; continue ;;
    esac
    if (( $# < 2 )) || [[ $2 == -* ]]; then die "Параметру $1 нужно значение (см. --help)."; fi
    v=$2
    case $1 in
      --ksc)          valid_fqdn "$(to_fqdn "$v")" || die "Неверный FQDN KSC: $v"
                      KSC_ADDR="https://$(to_fqdn "$v"):${KSC_PORT}" ;;
      --kvm)          valid_fqdn "$(to_fqdn "$v")" || die "Неверный FQDN Kaspersky VM: $v"
                      KVM_ADDR="https://$(to_fqdn "$v"):${KVM_PORT}" ;;
      -u|--user)      KSC_USER=$v ;;
      -t|--type)      [[ $v =~ ^(assets|vulnerabilities|software|all)$ ]] || die "Тип: assets, vulnerabilities, software или all."
                      RUN_TYPE=$v ;;
      --ip)           ip_filter_item "$v" >/dev/null || die "Неверный фильтр IP: $v"
                      F_IP=${v// /} ;;
      --importance)   F_IMPORTANCE=$(norm_levels "$v") || die "Значимость: числа от 0 до 4 через запятую."
                      ;;
      --priority)     F_PRIORITY=$(norm_levels "$v") || die "Приоритет: числа от 0 до 4 через запятую."
                      ;;
      --name)         F_NAME=$(trim "$v")
                      [[ -n $F_NAME ]] || die "Пустое имя ПО."
                      ;;
      -s|--page-size) [[ $v =~ ^[0-9]+$ ]] && (( v >= 1 && v <= MAX_PAGE_SIZE )) || die "Размер страницы: от 1 до ${MAX_PAGE_SIZE}."
                      PAGE_SIZE=$v ;;
      -o|--output)    [[ -d $v ]] || die "Папка не найдена: $v"
                      OUT_DIR=$(cd -- "$v" && pwd -P) ;;
      --cacert)       [[ -r $v ]] || die "Файл сертификата не читается: $v"
                      CACERT=$v ;;
      *)              die "Неизвестный параметр: $1 (см. --help)." ;;
    esac
    shift 2
  done
}

check_deps() {
  local c missing=()
  for c in curl base64 grep sed head tail cut awk mktemp date tr sort paste; do
    have "$c" || missing+=("$c")
  done
  if (( ${#missing[@]} )); then die "Не найдены утилиты: ${missing[*]}"; fi
}

merger_name() {
  if have python3; then printf 'python3'; elif have jq; then printf 'jq'; else printf 'встроенная'; fi
}

# ──────────────────────────────── Сценарии ────────────────────────────────

configure_interactive() {
  local def_kvm
  while true; do
    if [[ -n $KVM_ADDR ]]; then def_kvm=$(host_of "$KVM_ADDR"); else def_kvm=$(hostname -f 2>/dev/null || hostname); fi
    title "Подключение"
    ask_fqdn KSC_ADDR "Введите FQDN устройства с установленным Kaspersky Security Center" "$KSC_PORT" "$(host_of "$KSC_ADDR")"
    ask KSC_USER "Введите имя пользователя KSC" "$KSC_USER"
    ask_secret KSC_PASS "Введите пароль пользователя KSC"
    ask_fqdn KVM_ADDR "Введите FQDN устройства с установленным Kaspersky VM" "$KVM_PORT" "$def_kvm"
    printf '\n' >&2
    if start_session; then return 0; fi
    confirm "Необходимо ввести данные заново?" || exit 1
  done
}

show_menu() {
  local state="${C_RED}нет${C_RESET}"
  if [[ -n $TOKEN ]]; then state="${C_GREEN}активна${C_RESET}"; fi
  title "Какие данные необходимо выгрузить?"
  printf '  %s %s\n' "${C_DIM}KSC    ${C_RESET}" "${KSC_ADDR#https://} ${C_DIM}(${KSC_USER}, сессия:${C_RESET} ${state}${C_DIM})${C_RESET}" >&2
  printf '  %s %s\n' "${C_DIM}VM     ${C_RESET}" "${KVM_ADDR#https://}" >&2
  printf '  %s %s\n\n' "${C_DIM}Папка  ${C_RESET}" "$OUT_DIR" >&2
  menu_item 1 "Активы"     "${ENDPOINTS[assets]}"
  menu_item 2 "Уязвимости" "${ENDPOINTS[vulnerabilities]}"
  menu_item 3 "ПО"         "${ENDPOINTS[software]}"
  menu_item 4 "Всё указанное выше"  "три файла"
  menu_item 5 "Изменить подключение"
  menu_item 0 "Выход"
  printf '\n' >&2
}

menu_item() {  # menu_item КЛАВИША "Пункт" ["пояснение"] — выравнивание по символам, а не байтам
  local pad=$(( 14 - ${#2} ))
  if (( pad < 1 )); then pad=1; fi
  printf '  %s  %s%*s%s\n' "${C_BOLD}$1${C_RESET}" "$2" "$pad" '' "${3:+${C_DIM}$3${C_RESET}}" >&2
}

choose_filters() {  # choose_filters ТИП... — спрашивает, нужны ли фильтры, и какие
  local t
  clear_filters
  printf '\n' >&2
  confirm_no "Задать фильтры?" || return 0
  for t in "$@"; do ask_filters "$t"; done
}

run_interactive() {
  local choice=""
  [[ -t 0 ]] || die "Для меню нужен терминал. Для автоматического режима используйте -t (см. --help)."
  configure_interactive
  while true; do
    show_menu
    read -rp "  Ваш выбор: " choice || { printf '\n' >&2; break; }
    case $(trim "$choice") in
      1|2|3) choose_filters "${TYPES[choice - 1]}"; run_export "${TYPES[choice - 1]}" || true ;;
      4)     choose_filters "${TYPES[@]}"; run_export all || true ;;
      5)     end_session; configure_interactive ;;
      0|q|Q) break ;;
      *)     warn "Нет такого пункта: введите число от 0 до 5." ;;
    esac
  done
  printf '\n' >&2
  ok "Готово. Файлы лежат в ${OUT_DIR}"
}

run_batch() {
  [[ -n $KSC_ADDR ]] || die "Не указан адрес KSC (--ksc)."
  [[ -n $KVM_ADDR ]] || die "Не указан адрес Kaspersky VM (--kvm)."
  [[ -n $KSC_USER ]] || die "Не указан пользователь KSC (-u)."
  if [[ -z $KSC_PASS ]]; then
    [[ -t 0 ]] || die "Нет пароля: передайте его в переменной KSC_PASSWORD."
    ask_secret KSC_PASS "Пароль KSC для ${KSC_USER}"
  fi
  if [[ -n $F_IP && -n $F_IMPORTANCE ]] && ! can_filter_locally; then
    die "Для сочетания --ip и --importance нужен python3 или jq."
  fi
  start_session || exit 1
  local failed=0
  run_export "$RUN_TYPE" || failed=$?
  if (( failed )); then die "Не удалось выгрузить наборов: ${failed}."; fi
}

# ──────────────────────────────── Точка входа ────────────────────────────────

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  cursor_show
  end_session
  if [[ -n ${WORK_DIR:-} && -d $WORK_DIR ]]; then rm -rf -- "$WORK_DIR"; fi
  KSC_PASS=""
  exit "$rc"
}

main() {
  setup_ui
  trap cleanup EXIT
  trap 'printf "\n" >&2; warn "Прервано пользователем."; exit 130' INT
  trap 'exit 143' TERM

  parse_args "$@"
  check_deps
  [[ -w $OUT_DIR ]] || die "Нет прав на запись в папку ${OUT_DIR}"
  WORK_DIR=$(mktemp -d "${OUT_DIR}/.kasperskyvm_api_helper.XXXXXX")
  if [[ -n $CACERT ]]; then TLS_OPTS=(--cacert "$CACERT"); else TLS_OPTS=(--insecure); fi

  banner
  if [[ -z $CACERT ]]; then
    printf '  %s\n' "${C_DIM}Проверка TLS-сертификатов выключена (как curl -k).${C_RESET}" >&2
    printf '  %s\n' "${C_DIM}Как включить: ./${SCRIPT_NAME} --tls-help${C_RESET}" >&2
  else
    printf '  %s\n' "${C_DIM}Проверка TLS-сертификатов: ${CACERT}${C_RESET}" >&2
  fi
  printf '  %s\n' "${C_DIM}Склейка страниц: $(merger_name)${C_RESET}" >&2

  if [[ -n $RUN_TYPE ]]; then run_batch; else run_interactive; fi
}

main "$@"
