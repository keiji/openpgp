@file:Suppress("MagicNumber")

package dev.keiji.openpgp.packet.userattribute.subpacket

enum class SubpacketType(val value: Int) {
    Image(1),
    PrivateOrExperimental100(100),
    PrivateOrExperimental101(101),
    PrivateOrExperimental102(102),
    PrivateOrExperimental103(103),
    PrivateOrExperimental104(104),
    PrivateOrExperimental105(105),
    PrivateOrExperimental106(106),
    PrivateOrExperimental107(107),
    PrivateOrExperimental108(108),
    PrivateOrExperimental109(109),
    PrivateOrExperimental110(110),
    ;

    companion object {
        fun findBy(value: Int) = values().firstOrNull { it.value == value }
    }
}
