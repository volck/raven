package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestCreatek8sSecret(t *testing.T) {
	t.Parallel()
	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	config := config{
		vaultEndpoint: cluster.Cores[0].Client.Address(),
		secretEngine:  "kv",
		token:         client.Token(),
		destEnv:       "kv",
	}

	// make testable secrets for cluster
	secrets := map[string]interface{}{
		"data":     map[string]interface{}{"secretKey": "secretValue"},
		"metadata": map[string]interface{}{"version": 2},
	}
	client.Logical().Write("kv/data/secret", secrets)

	singleSecret := getSingleKV(client, "kv", "secret")
	k8sSecret := createK8sSecret("secret", config, singleSecret)
	if k8sSecret.Data == nil && k8sSecret.StringData == nil {
		t.Fatal("k8sSecret nil, data not loaded")
	}
	fmt.Println("k8sSecret", k8sSecret)
}

func TestCreatek8sSecretwWithBase64Data(t *testing.T) {
	// init client
	t.Parallel()
	cluster := createVaultTestCluster(t)
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	config := config{
		vaultEndpoint: cluster.Cores[0].Client.Address(),
		secretEngine:  "kv",
		token:         client.Token(),
		destEnv:       "kv",
	}
	//create base64Datasecret
	b64DataSecret := map[string]interface{}{
		"data": map[string]interface{}{"b64secretData": `base64:LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZWekNDQXorZ0F3SUJBZ0lKQU9MTEw2V2Va
b0VrTUEwR0NTcUdTSWIzRFFFQkN3VUFNRUl4Q3pBSkJnTlYKQkFZVEFsaFlNUlV3RXdZRFZRUUhE
QXhFWldaaGRXeDBJRU5wZEhreEhEQWFCZ05WQkFvTUUwUmxabUYxYkhRZwpRMjl0Y0dGdWVTQk1k
R1F3SGhjTk1qRXdOekF4TURVek16UXpXaGNOTWpJd056QXhNRFV6TXpReldqQkNNUXN3CkNRWURW
UVFHRXdKWVdERVZNQk1HQTFVRUJ3d01SR1ZtWVhWc2RDQkRhWFI1TVJ3d0dnWURWUVFLREJORVpX
WmgKZFd4MElFTnZiWEJoYm5rZ1RIUmtNSUlDSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQWc4QU1J
SUNDZ0tDQWdFQQp0bGpEVEhibkJ0NlNJcDBRMW01RC9tbW9MdnJoeWJRRDFBa1VHTDVrSjhZcmdZ
OG5JSjM2bWRxemhma3dlcVViCkRPUzhOcEpzcHhjdlgyZWlRS1k5TWM1Vm9xa25FMC9lM1doRWdK
RndYYmRqREppdUlLNS8vcjFPM1NpKzArSWUKRUo1WWx3OWFYR0lJOWs0V1d0REFMMktlY1JrNWc5
VFlmTzdwRjd4TGRjUlhCcWNIbCszbUxDVnFQYXFpNEY3bgpnVDhwRjBtOG9HOHdCMXNvNzN1RFlt
NkRJd0VTVk55VytBL21oMGRZbk8rTHZaVURCb1pFaUcxMUdXTDY1bzBXClJwejZ1STYwRTR0NEVP
ZEt1UFBwM0FueHVHWnk5TzlZTWdJVHpUQjFSazJOOGxPT25jRzZtanRTN0cyZFRhOEMKVVJxc2pu
RldxZEpLRHNsTFhhWk05eEo3d3pVeStpaE5SKy91UEZKSXpEVXlFMVRNQjZGSDdLcysrQ0lzTm9N
VwpydFN4ckM4MlZ2UTdVSkViaGJ5azRqNXhWSzhWYk43M0dJOXNwN21mR0dBQnJKT2RkYTU5R0Yx
bUJHYllsMHdWCndvY2lIanozWjhMWXZKNXpCQjNSS1JGT1NGUXc3RTI3QzR0dXNXNTk3T2Z5MCta
R0VqQnR0QTZwV25BZjMzZ2sKTVVQMTYwczdTTGJ1dUNER2l2VmhDNlhkMDBJbTh0NGFmRUwxYmx6
M2tWd3pKR1ZMME94OFlSaUpROUY5czYycwpvRHdJNERPWHN5dTV2dUkxRmVXSVRRendxdnpXZjJR
VkM3NmVyR21xa00zcFdnUURtVHoyalNzbCt3ZS9BK1dCCmtUY0RiYXFuVWN6d0RUM2pMeXRleFVR
KzFpcUIxb3VjeXA0UUk5RnJ3ajhDQXdFQUFhTlFNRTR3SFFZRFZSME8KQkJZRUZPamk5SWJIVzFx
VFEwWHFyQlBHLzY2MlBJYkFNQjhHQTFVZEl3UVlNQmFBRk9qaTlJYkhXMXFUUTBYcQpyQlBHLzY2
MlBJYkFNQXdHQTFVZEV3UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dJQkFDdXQvVmMw
CktLK0tPQ0xNU0JxbnFzaUppZW1FdUpEYXlKMFp3akpQT3JjSXJtY1FvcTdJODJDZ1pEeEMvK3Uy
aXVLc0JzU2oKMHF1aWpLRVhvcDg2QjkwZWFBVjUwcXRtZHpiNW84YTdwTFF2MmxHUGhreHVVcTR6
Ylk4Rkx4ZmhmMnBhQk5YTgpHM0ZPZU9wMkgxSWJkSWZyOVptL0x1UjkwQmJ3Mmh3SkVKSFNiTjZl
STE3ZFJwaVBFdlVuY09kS0M5Z1dFdVd2CjVNMkU5c1creS9TOU1LSEdkSWJCNjBLMjA1WjZrS1hx
ckNnWlg5Q1NNc3YwUDNoaFVqQmFCQWtmV0hQUU9BdVUKSG5yb2J5UG9kMmltN1RwZXdMZ1VvM1V5
UlVXT2lxdjNaMjZpZnZLNS8xNzJKaHFBRVpTTFQ3N095YkZIdzdPMApLc1VCVlBlQ3huWlhQNGlx
eWhYNHRoMkpXUHljaXlqTXB4TzhSd3hYKzBhVnErZnJYZmNrM0laalRqOSt4blI2Cld5RnlGVVZP
Z2VhOElzRXZReVo5WllOUVJKYWxkYnhZb0N5eGs1NFYydTdIdDUyU2hJWEtaam5INms3YVBTa2MK
c1FuUEc0THJRell3K3d1REtPTDZNZXpSbURsYzhvaHo5MVZrem9JVytxcXY5VTBUS3hjWCtGN01X
YkJCNjBoQgpVcVJoejVzY2Zmem5pdUJqNHJzdkcvQlRlR2NFVnZzSVZwRE5oRmF2OFNUaWYzNVB0
L1drYUxSaTh4OWVObElXCmRQZTc2anNVVHFMeTBDeVVtSDZDWk5ObTVKUVlIRzlBd3hUUkJiMCtU
Ri9YQklaeCtFU1VOcUlDR0JrV0hvNDUKZEpGM0UvN09NellDT1hEQ3lNR1lQZzBMQlJGNEJBM2tW
emxMCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
`},
		"metadata": map[string]interface{}{"version": 2},
	}
	// write testobject
	client.Logical().Write("kv/data/b64data", b64DataSecret)
	singleSecret := getSingleKV(client, "kv", "b64data")
	k8sSecret := createK8sSecret("b64data", config, singleSecret)
	for _, v := range k8sSecret.Data {
		if strings.Contains(string(v), "base64") {
			t.Fatal("base64 not trimmed")
		}

	}

}
