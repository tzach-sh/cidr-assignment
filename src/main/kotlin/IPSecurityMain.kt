import cidr.security.*

fun main(args: Array<String>) {
    val blockIpRange = listOf("172.16.0.1/23", "172.16.0.1/8", "192.16.8.1/4")
    val ipRequestList = listOf("172.16.0.1", "216.254.128.0")
    val blackList = CidrRequests(blockIpRange)
    println(blackList.unauthorizedIpAddresses)
    ipRequestList.forEach {
        if (blackList.isAllowed(it)) {
            println("ip $it is authorized")
        } else {
            println("ip $it is not authorized!")
        }
    }


}