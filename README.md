# tracer
압축 해제프로그램 hoonzip을 퍼징하기 위해 만든 퍼저 tracer입니다.
# 사용법
## 1. 소스코드 빌드
![image](https://github.com/zlwhro/tracer/assets/113174616/3fc33aba-930e-4049-82ba-3b03c81eeab1)

먼저 소스코드를 빌드해주세요 그러면 실행파일 tracer와 공유 라이브러리 파일 fuzzhook.so 가 생성됩니다. tracer와 fuzzhook.so는 같은 폴더에 있어야 합니다.

## 2. 테스트 바이너리 hoonzip 준비
![image](https://github.com/zlwhro/tracer/assets/113174616/6b234ecf-c172-499c-98f9-e2b55644bd16)

tracer로 테스트할 바이너리는 hoonzip입니다. 깃허브 주소가 있습니다.
https://github.com/zlwhro/hoonzip.git

## 3. 바이너리 경로 입력
![image](https://github.com/zlwhro/tracer/assets/113174616/9fbad3ae-cde2-4ad5-bb9a-267a5258df31)

tracer를 실행하면 먼저 퍼징할 바이너리 경로를 입력합니다. 지금은 같은 폴더에 있기 때문에 파일 이름만 입력합니다.

## 4. seed 파일 입력
![image](https://github.com/zlwhro/tracer/assets/113174616/cdde289e-dd88-454d-b026-31d9842e9c1d)

그 다음 시도로 사용할 파일의 위치를 입력해주세요

## 5. 스냅샷 포인트 지정
![image](https://github.com/zlwhro/tracer/assets/113174616/e0861022-7c62-4b8c-b1a1-958f10fd2d92)

tracer는 원하는 함수만 퍼징하기 위해서 원하는 지점에서 스냅샷을 저장하고 지정한 위치에 도달하면 스냅샷을 복구하는 방식으로 동작합니다.

스냅샷을 저장할 지점을 선택해주세요 함수 이름을 입력하거나 오프셋을 입력하세요 그러면 tracer가 프로세스를 해당 지점까지 실행하고 그 시점의 레지스터, 할당된 힙, 파일 오프셋을 저장합니다.

완전한 스냅샷 구현을 위해서 메모리에 쓴 값도 되돌릴 필요가 있지만 퍼징 대상으로 사용할 함수에서 필요하지 않고 시간이 부족했습니다.

![image](https://github.com/zlwhro/tracer/assets/113174616/b995cfff-d8a5-4d6f-bc68-617221ef1719)

3 번을 선택하면 퍼징할 바이너리의 심볼테이블을 읽고 심볼의 이름과 오프셋이 표시됩니다.

![image](https://github.com/zlwhro/tracer/assets/113174616/3f65c220-8b46-4042-a96b-4acd5ccf0b70)

퍼징할 함수는 ZIP_Decompress입니다. hoonzip에서 압축해제를 담당하는 함수입니다. 다른 함수도 선택할 수 있지만 스냅샷 구현이 부족해 제대로 동작하지 않습니다.

![image](https://github.com/zlwhro/tracer/assets/113174616/2717bf04-e9e3-4dc2-826a-dae970adce14)

1 번을 선택하고 ZIP_Decompress를 설정해 주세요

![image](https://github.com/zlwhro/tracer/assets/113174616/13aa3d50-5db3-4e4d-90fc-a06485c9207d)

함수이름으로 스냅샷 포인트를 설정하면 스냅샷 복구 위치는 그 함수가 리턴하는 지점으로 설정됩니다.

## 6. mutation 설정
![image](https://github.com/zlwhro/tracer/assets/113174616/216345a0-c9c1-4606-a12a-ed099244399e)

이제 mutation을 설정합니다. mutation_idx 와 mutation_size를 선택해주세요 mutation_idx는 파일에서 mutation을 적용할 위치 mutation_size는 그 크기를 말합니다.

예를 들어 mutation_idx 가 70이고 mutation_size 가 10000 이면 전체 파일에서 70 ~ 10070 위치에 있는 바이트 중 %1가 랜덤으로 변형됩니다.

지금은 압축 해제를 담당하는 ZIP_Decompess 함수만 퍼징할 것이기 때문에 zip 파일에서 헤더 부분은 그대로 두고 실제 압축 데이터가 저장된 부분만 변형해야합니다.

![image](https://github.com/zlwhro/tracer/assets/113174616/95cf8003-b672-47f8-906d-51593e2b7c36)

hoonzip의 -l 옵션으로 압축 데이터가 저장된 오프셋과 압축된 크기를 알 수 있습니다. 한번 자신이 가진 다른 zip 파일로 시험해 보세요

## 7. 반복횟수 설정
![image](https://github.com/zlwhro/tracer/assets/113174616/57ff9733-be5c-4b2c-815f-e2ef4173cd9c)

이제 몇번을 반복할지 입력합니다. 저는 1000번 반복해 보겠습니다.

## 8. 저장위치 설정
![image](https://github.com/zlwhro/tracer/assets/113174616/f7b2c40e-2980-4f91-af46-e34ca8507055)

마지막으로 mutation으로 생성한 zip 파일을 저장할 폴더를 설정합니다. 저는 /tmp로 설정했습니다.
## 9. 퍼징 실행
![image](https://github.com/zlwhro/tracer/assets/113174616/6fb37ea8-09c9-4a64-8b88-7127e06d776a)

설정이 완료되면 퍼징을 실행합니다. 그리고 충돌이 발생하면 그 충돌을 발생시킨 zip 파일을 위에서 지정한 폴더에 저장합니다.

## 10. 결과 확인
![image](https://github.com/zlwhro/tracer/assets/113174616/0ed43825-d960-4ec4-8098-e5a0b7c221c5)

스냅샷 기능이 부족하기 때문에 ZIP_Decompress 외에 다른 함수에서는 제대로 작동하지 않습니다. 퍼저에서 충돌이 발생해도 실제로 실행해보면 충돌이 발생하지 않는 경우가 있습니다.

그래도 ZIP_Decompess 함수에서는 올바르게 찾았네요

tracer의 대부분의 작업은 메모리 내에서만 이루어집니다. 파일 I/O를 실행할 때는 프로그램을 처음 로드할 때와 충돌이 발생한 파일을 저장할 때 뿐입니다. 이 방법은 프로그램을 매번 실행하고 파일 I/O를 매번 실행하는 것보다 빠릅니다.

# referrence

Fuzz like a caveman
https://blog.tartanllama.xyz/writing-a-linux-debugger-setup/

Writing a Linux Debugger
https://blog.tartanllama.xyz/writing-a-linux-debugger-setup/














