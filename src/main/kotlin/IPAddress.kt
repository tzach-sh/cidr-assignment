package cidr.security


class IPAddress(var ipAddress: String) {
    var binaryIpAddressArray: List<String>? = null
    val ipRegex = """\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}\b""".toRegex()

    init {
        if (ipAddress.matches(ipRegex)) {
            binaryIpAddressArray = ipToBinary(ipAddress)
        } else {
            throw IllegalArgumentException("IP not in the right format: $ipAddress")
        }
    }


    private fun splitIp(ip: String): List<Int> {
        return ip.split('.').map { it.toInt() }
    }

    private fun ipToBinary(ip: String): List<String> {
        val splittedIp = splitIp(ip)
        return splittedIp.map { toBinaryString(it) }
    }

    private fun toBinaryString(decimalNumber: Int): String {
        val binaryString = Integer.toBinaryString(decimalNumber)
        return if (binaryString.length == 8) {
            binaryString
        } else {
            binaryString.padStart(8, '0')
        }
    }

    fun ipToLong(): Long {
        val splittedIp = splitIp(ipAddress)
        var result = 0.0
        splittedIp.forEachIndexed { ndx, item ->
            val power = 3 - ndx
            result += item.toLong() shl (8 * (power))
        }
        return result.toLong()
    }

}
